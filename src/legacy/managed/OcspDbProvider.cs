// OcspDbProvider.cs
//   AD CS 联机响应程序的自定义吊销提供程序：数据源 = 证书数据库快照（非 CRL）。
//
//   * OcspDbProvider        —— 实现 IOCSPRevInfoProvider，被 ocspsvc.exe 进程内加载
//   * RevDbSync             —— 命令行：把 CA 数据库导成快照文件（用 certutil -view）
//
//   接口/结构体取自 C:\Windows\System32\ocsprevp.dll 的类型库 {8A47B139-2245-430F-87A5-CB268331302F}：
//     IOCSPRevInfoProvider        {93F568FF-B8C7-483B-8DEF-5E6EEF8B7650}
//       0 Initialize(BSTR caId, CERTTRANSBLOB* caCert, CERTTRANSBLOB* config)
//       1 VerifySerialNumber(CERTTRANSBLOB* serial, RevStatusInfo* status)
//       2 GetConfigInformation(CERTTRANSBLOB* config)
//       3 GetProviderManager(IOCSPRevInfoProviderManager** mgr)
//     IOCSPRevInfoProviderManager {F85C5127-F108-497D-8FCC-B2A709047C98}
//     RevStatusInfo { DWORD dwStatus; FILETIME ftThisUpdate, ftNextUpdate, ftNextPublish,
//                     ftRevocationDate; DWORD dwRevocationReason; }   // 40 bytes
//
//   构建：
//     csc /target:library /out:OcspDbProvider.dll OcspDbProvider.cs
//     csc /target:exe     /out:RevDbSync.exe   OcspDbProvider.cs /define:SYNC_ONLY
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

// ---------------------------------------------------------------- 共享结构

[StructLayout(LayoutKind.Sequential)]
public struct CERTTRANSBLOB
{
    public uint cb;
    public IntPtr pb;
}

// 原生侧是紧密排列：dwStatus(4) + 4×FILETIME(8) + dwReason(4) = 40 字节。
// 必须 Pack=1，否则 C# 按 8 字节对齐会插 4 字节填充，时间字段整体错位（OCSP 里表现为 Bad time value）。
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct RevStatusInfo
{
    public uint dwStatus;
    public long ftThisUpdate;
    public long ftNextUpdate;
    public long ftNextPublish;
    public long ftRevocationDate;
    public uint dwRevocationReason;
}

[ComImport, Guid("93F568FF-B8C7-483B-8DEF-5E6EEF8B7650"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IOCSPRevInfoProvider
{
    [PreserveSig] int Initialize([MarshalAs(UnmanagedType.BStr)] string bstrCAId,
                                ref CERTTRANSBLOB pcCACertificate,
                                ref CERTTRANSBLOB pcConfigInformation);
    [PreserveSig] int VerifySerialNumber(ref CERTTRANSBLOB pcSerialNumber,
                                         out RevStatusInfo pRevStatusInfo);
    [PreserveSig] int GetConfigInformation(out CERTTRANSBLOB pConfigInformation);
    [PreserveSig] int GetProviderManager(out IntPtr pIManager);
}

[ComImport, Guid("F85C5127-F108-497D-8FCC-B2A709047C98"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
public interface IOCSPRevInfoProviderManager
{
    [PreserveSig] int GetProviderInformation(out IntPtr pbstrName, out IntPtr pbstrDescription);
    [PreserveSig] int Configure(IntPtr hwndParent, [MarshalAs(UnmanagedType.BStr)] string bstrCAConfigId,
                                ref CERTTRANSBLOB pcCACertificate, ref CERTTRANSBLOB pcInConfigInformation,
                                out int pbModified, out CERTTRANSBLOB pOutConfigInformation);
    [PreserveSig] int View(IntPtr hwndParent, [MarshalAs(UnmanagedType.BStr)] string bstrCAConfigId,
                           ref CERTTRANSBLOB pcCACertificate, ref CERTTRANSBLOB pcInConfigInformation);
    [PreserveSig] int GetStatus([MarshalAs(UnmanagedType.BStr)] string bstrCAConfigId,
                                ref CERTTRANSBLOB pcCACertificate, ref CERTTRANSBLOB pcInConfigInformation,
                                out IntPtr pVarStatus, out int pHRStatus);
    [PreserveSig] int Initialize([MarshalAs(UnmanagedType.BStr)] string bstrCAConfigId,
                                 ref CERTTRANSBLOB pcCACertificate, out CERTTRANSBLOB pOutConfigInformation);
}

// ---------------------------------------------------------------- 快照读写

public sealed class RevSnapshot
{
    public sealed class Entry
    {
        public int Disposition;
        public long RevokedWhenUtc;     // 0 = 未吊销
        public int Reason;
        public long NotAfterUtc;
    }

    public readonly Dictionary<string, Entry> Map = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
    public long LoadedUtc;
    public string Path;
    public int Count { get { return Map.Count; } }

    /// <summary>序列号统一成大写十六进制、去前导 0（DB 与 OCSP 请求的写法可能不同）。</summary>
    public static string NormSerial(string hex)
    {
        if (hex == null) return "";
        var sb = new StringBuilder(hex.Length);
        foreach (char c in hex)
        {
            if (Uri.IsHexDigit(c)) sb.Append(char.ToUpperInvariant(c));
        }
        string s = sb.ToString().TrimStart('0');
        return s.Length == 0 ? "0" : s;
    }

    public static string SerialFromBlob(CERTTRANSBLOB blob)
    {
        if (blob.pb == IntPtr.Zero || blob.cb == 0) return "";
        var buf = new byte[blob.cb];
        Marshal.Copy(blob.pb, buf, 0, (int)blob.cb);
        var sb = new StringBuilder(buf.Length * 2);
        foreach (byte b in buf) sb.Append(b.ToString("X2"));
        return NormSerial(sb.ToString());
    }

    public bool Load(string path)
    {
        try
        {
            var map = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (var sr = new StreamReader(fs, Encoding.UTF8))
            {
                string line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (line.Length == 0 || line[0] == '#') continue;
                    string[] f = line.Split('\t');
                    if (f.Length < 5) continue;
                    var e = new Entry();
                    int d, r;
                    long rv, na;
                    if (!int.TryParse(f[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out d)) continue;
                    long.TryParse(f[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out rv);
                    int.TryParse(f[3], NumberStyles.Integer, CultureInfo.InvariantCulture, out r);
                    long.TryParse(f[4], NumberStyles.Integer, CultureInfo.InvariantCulture, out na);
                    e.Disposition = d; e.RevokedWhenUtc = rv; e.Reason = r; e.NotAfterUtc = na;
                    map[NormSerial(f[0])] = e;
                }
            }
            Map.Clear();
            foreach (var kv in map) Map[kv.Key] = kv.Value;
            LoadedUtc = DateTime.UtcNow.Ticks;
            Path = path;
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("[revdb] load failed: " + ex.Message);
            return false;
        }
    }
}

// ---------------------------------------------------------------- 提供程序

[ComVisible(true)]
[Guid("7B0C4B1E-93A1-4C0F-9E52-0D2A6A5B41C9")]
[ProgId("NasOcsp.DbRevInfoProvider.1")]
[ClassInterface(ClassInterfaceType.None)]
public sealed class OcspDbProvider : IOCSPRevInfoProvider
{
    // dwStatus 的取值语义（可用配置覆盖，便于实测校准）
    static int s_valid = 0;
    static int s_revoked = 1;
    static int s_unknown = 0;

    static readonly object s_lock = new object();
    static RevSnapshot s_snap = new RevSnapshot();
    static string s_dir = @"C:\ProgramData\OcspDbProvider";
    static string s_snapPath = @"C:\ProgramData\OcspDbProvider\revdb.dat";
    static int s_maxAgeSec = 90;
    static string s_force = "";          // 调试用：valid / revoked / unknown（空 = 正常查表）
    static string s_source = "snapshot";     // live = 直接查 CA 数据库；snapshot = 只读快照
    static string s_caCfg = "";          // 空 = 自动用 <本机名>\<CA 名>
    static string s_caName = "";
    static int s_liveCacheSec = 5;
    static long s_nextCheckTicks;
    static bool s_iniLoaded;
    static int s_calls;
    static OcspDbProviderManager s_manager;      // 托住对象，防 GC 回收后回调踩空
    static IntPtr s_managerIface;
    // 联机响应程序把持久化的配置 blob 传给 Initialize，并期望 GetConfigInformation 原样吐回来
    // （内置 ocsprevp 就是这么做的）。回环不一致会被判成"配置无效" → 所有请求 unauthorized。
    static byte[] s_inConfigBlob = new byte[0];

    sealed class LiveEntry
    {
        public int Status;      // 1 = 有效, 2 = 已吊销, 0 = 未知
        public int Reason;
        public long ExpiresTicks;
    }
    static readonly Dictionary<string, LiveEntry> s_live = new Dictionary<string, LiveEntry>(StringComparer.OrdinalIgnoreCase);
    static Type s_adminType;
    static object s_admin;

    /// <summary>CCertAdmin (certadm.dll)：ICertAdmin2 是 dual 接口，用 IDispatch 调用即可。</summary>
    const string CCertAdminClsid = "37eabaf0-7fb6-11d0-8817-00a0c903b83c";

    static string CaConfigString()
    {
        if (s_caCfg.Length > 0) return s_caCfg;
        string ca = s_caName.Length > 0 ? s_caName : "CA-NAME";
        return Environment.MachineName + @"\" + ca;
    }

    /// <summary>
    /// 直接问 CA 数据库（RPC 到 certsvc）。返回码实测语义：
    ///   3 = 有效, 2 = 已吊销（再取 GetRevocationReason 得原因）, 4 = 库里没有该序列号。
    /// 注意 config 串必须带主机名前缀，否则 CCertView/CCertAdmin 报 RPC_S_SERVER_UNAVAILABLE。
    /// </summary>
    static bool TryLive(string serial, out int status, out int reason)
    {
        status = 0; reason = 0;
        long nowTicks = DateTime.UtcNow.Ticks;
        LiveEntry hit;
        if (s_live.TryGetValue(serial, out hit) && hit.ExpiresTicks > nowTicks)
        {
            status = hit.Status; reason = hit.Reason;
            return true;
        }
        try
        {
            if (s_adminType == null) s_adminType = Type.GetTypeFromCLSID(new Guid(CCertAdminClsid));
            if (s_admin == null) s_admin = Activator.CreateInstance(s_adminType);

            object ret = s_adminType.InvokeMember("IsValidCertificate",
                System.Reflection.BindingFlags.InvokeMethod, null, s_admin,
                new object[] { CaConfigString(), serial });
            int code = Convert.ToInt32(ret, CultureInfo.InvariantCulture);
            int why = 0;
            try
            {
                object r2 = s_adminType.InvokeMember("GetRevocationReason",
                    System.Reflection.BindingFlags.InvokeMethod, null, s_admin, new object[0]);
                why = Convert.ToInt32(r2, CultureInfo.InvariantCulture);
            }
            catch { }
            status = code == 3 ? 1 : (code == 2 ? 2 : 0);
            reason = why;
            var e = new LiveEntry();
            e.Status = status; e.Reason = reason;
            e.ExpiresTicks = nowTicks + TimeSpan.FromSeconds(s_liveCacheSec).Ticks;
            s_live[serial] = e;
            return true;
        }
        catch (Exception ex)
        {
            Log("[revdb] live lookup failed (" + serial + "): " + ex.Message + "  -> snapshot fallback");
            s_admin = null;
            return false;
        }
    }

    static readonly object s_logLock = new object();

    static void Log(string msg)
    {
        try
        {
            lock (s_logLock)
            {
                string dir = System.IO.Path.GetDirectoryName(s_snapPath);
                Directory.CreateDirectory(dir);
                string file = System.IO.Path.Combine(dir, "provider.log");
                var fi = new FileInfo(file);
                if (fi.Exists && fi.Length > 1024 * 1024) fi.Delete();
                using (var fs = new FileStream(file, FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
                {
                    byte[] line = Encoding.UTF8.GetBytes(
                        DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg + "\r\n");
                    fs.Write(line, 0, line.Length);
                }
            }
        }
        catch { }
    }

    /// <summary>快照超过 maxAge 就重读一次（文件被同步程序原子替换）。</summary>
    static RevSnapshot Current()
    {
        lock (s_lock)
        {
            LoadIni();
            long now = DateTime.UtcNow.Ticks;
            if (now >= s_nextCheckTicks || s_snap.Count == 0)
            {
                s_nextCheckTicks = now + TimeSpan.FromSeconds(5).Ticks;
                var fresh = new RevSnapshot();
                if (fresh.Load(s_snapPath)) s_snap = fresh;
                else Log("[revdb] snapshot missing: " + s_snapPath);
            }
            return s_snap;
        }
    }

    /// <summary>配置 blob = UTF-8 文本 name=value;name=value</summary>
    static void ApplyConfig(string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        foreach (string part in text.Split(new char[] { ';', '\n', '\r' }))
        {
            string s = part.Trim();
            if (s.Length == 0) continue;
            int eq = s.IndexOf('=');
            if (eq <= 0) continue;
            ApplyOne(s.Substring(0, eq), s.Substring(eq + 1));
        }
    }

    /// <summary>provider.ini：不依赖联机响应程序怎么序列化配置，自己读文件，改完重启服务即可生效。</summary>
    static void LoadIni()
    {
        if (s_iniLoaded) return;
        s_iniLoaded = true;
        try
        {
            string ini = System.IO.Path.Combine(s_dir, "provider.ini");
            if (!File.Exists(ini)) return;
            foreach (string raw in File.ReadAllLines(ini, Encoding.UTF8))
            {
                string s = raw.Trim();
                if (s.Length == 0 || s[0] == '#' || s[0] == ';') continue;
                int eq = s.IndexOf('=');
                if (eq <= 0) continue;
                ApplyOne(s.Substring(0, eq), s.Substring(eq + 1));
            }
            Log("[revdb] ini loaded: snapshot=" + s_snapPath + " maxage=" + s_maxAgeSec +
                " valid=" + s_valid + " revoked=" + s_revoked + " unknown=" + s_unknown + " force=" + s_force);
        }
        catch (Exception ex) { Log("[revdb] ini failed: " + ex.Message); }
    }

    static void ApplyOne(string key, string value)
    {
        string k = key.Trim().ToLowerInvariant();
        string v = value.Trim();
        int iv;
        switch (k)
        {
            case "snapshot":
                if (v.Length > 0) s_snapPath = v;
                break;
            case "maxage":
                if (int.TryParse(v, out iv) && iv > 0) s_maxAgeSec = iv;
                break;
            case "validstatus":
                if (int.TryParse(v, out iv)) s_valid = iv;
                break;
            case "revokedstatus":
                if (int.TryParse(v, out iv)) s_revoked = iv;
                break;
            case "unknownstatus":
                if (int.TryParse(v, out iv)) s_unknown = iv;
                break;
            case "force":
                s_force = v.ToLowerInvariant();
                break;
            case "source":
                s_source = v.ToLowerInvariant();
                break;
            case "ca":
                s_caCfg = v;
                break;
            case "caname":
                s_caName = v;
                break;
            case "livecache":
                if (int.TryParse(v, out iv) && iv >= 0) s_liveCacheSec = iv;
                break;
        }
    }

    static long FileTime(DateTime utc)
    {
        try { return utc.ToFileTimeUtc(); } catch { return 0; }
    }

    // ---- IOCSPRevInfoProvider ----

    public int Initialize(string bstrCAId, ref CERTTRANSBLOB pcCACertificate, ref CERTTRANSBLOB pcConfigInformation)
    {
        try
        {
            string cfg = "";
            if (pcConfigInformation.pb != IntPtr.Zero && pcConfigInformation.cb > 0)
            {
                var buf = new byte[pcConfigInformation.cb];
                Marshal.Copy(pcConfigInformation.pb, buf, 0, (int)pcConfigInformation.cb);
                s_inConfigBlob = buf;                       // 原样保存，GetConfigInformation 回吐
                cfg = Encoding.UTF8.GetString(buf).TrimEnd('\0');
            }
            ApplyConfig(cfg);
            if (bstrCAId != null && bstrCAId.Length > 0)
            {
                // 响应程序传进来的通常是 "<CA 名>"，也可能带主机前缀
                int bs = bstrCAId.IndexOf('\\');
                s_caName = bs >= 0 ? bstrCAId.Substring(bs + 1) : bstrCAId;
            }
            var s = Current();
            Log("[revdb] Initialize ca=" + bstrCAId + " source=" + s_source + " caCfg=" + CaConfigString() +
                " snapshot entries=" + s.Count + " cfg=[" + cfg + "]");
            return 0;
        }
        catch (Exception ex)
        {
            Log("[revdb] Initialize failed: " + ex);
            return unchecked((int)0x80004005);
        }
    }

    public int VerifySerialNumber(ref CERTTRANSBLOB pcSerialNumber, out RevStatusInfo st)
    {
        DateTime now = DateTime.UtcNow;
        st = new RevStatusInfo();
        st.ftThisUpdate = FileTime(now);
        st.ftNextUpdate = FileTime(now.AddMinutes(30));
        st.ftNextPublish = FileTime(now.AddHours(2));   // 必须晚于 nextUpdate
        st.dwRevocationReason = 0;
        try
        {
            string serial = RevSnapshot.SerialFromBlob(pcSerialNumber);
            s_calls++;
            if (s_calls <= 5 || (s_calls % 50) == 0) Log("[revdb] request #" + s_calls + " serial=" + serial);
            if (s_force == "valid") { st.dwStatus = (uint)s_valid; return 0; }
            if (s_force == "revoked")
            {
                st.dwStatus = (uint)s_revoked;
                st.dwRevocationReason = 4;               // 调试：固定按"已移除"回答
                st.ftRevocationDate = FileTime(now.AddMinutes(-1));
                return 0;
            }
            if (s_force == "unknown") { st.dwStatus = (uint)s_unknown; return 0; }

            RevSnapshot.Entry e;
            bool haveSnap = Current().Map.TryGetValue(serial, out e);

            // ---- 首选：直接查 CA 数据库（RPC，config 串带主机前缀）----
            if (s_source == "live")
            {
                int liveStatus, liveReason;
                if (TryLive(serial, out liveStatus, out liveReason))
                {
                    if (liveStatus == 2)                       // 已吊销
                    {
                        st.dwStatus = (uint)s_revoked;
                        st.dwRevocationReason = (uint)liveReason;
                        // 吊销时间 ICertAdmin 不给，用快照里的；没有就让响应程序用当前时间
                        st.ftRevocationDate = (haveSnap && e.RevokedWhenUtc > 0) ? e.RevokedWhenUtc : FileTime(now);
                    }
                    else if (liveStatus == 1)                  // 有效
                    {
                        st.dwStatus = (uint)s_valid;
                        st.ftRevocationDate = 0;
                    }
                    else                                       // 库里没有
                    {
                        st.dwStatus = (uint)s_unknown;
                    }
                    return 0;
                }
            }

            // ---- 兜底：读快照 ----
            if (!haveSnap)
            {
                st.dwStatus = (uint)s_unknown;
                return 0;
            }
            if (e.Disposition == 21)                  // 已吊销
            {
                st.dwStatus = (uint)s_revoked;
                st.dwRevocationReason = (uint)e.Reason;
                st.ftRevocationDate = e.RevokedWhenUtc > 0 ? e.RevokedWhenUtc : FileTime(now);
            }
            else if (e.Disposition == 20 || e.Disposition == 15 || e.Disposition == 14)   // 有效 / CA 证书
            {
                st.dwStatus = (uint)s_valid;
                st.ftRevocationDate = 0;
            }
            else                                      // 未决、拒绝、错误……
            {
                st.dwStatus = (uint)s_unknown;
            }
            return 0;
        }
        catch (Exception ex)
        {
            Log("[revdb] VerifySerialNumber failed: " + ex);
            st.dwStatus = (uint)s_unknown;
            return 0;
        }
    }

    public int GetConfigInformation(out CERTTRANSBLOB blob)
    {
        blob = new CERTTRANSBLOB { cb = 0, pb = IntPtr.Zero };
        try
        {
            byte[] buf;
            if (s_inConfigBlob != null && s_inConfigBlob.Length > 0)
            {
                buf = s_inConfigBlob;                       // 回环：原样返回
            }
            else
            {
                string cfg = "source=" + s_source + ";caname=" + s_caName + ";livecache=" + s_liveCacheSec +
                             ";snapshot=" + s_snapPath + ";maxage=" + s_maxAgeSec +
                             ";validstatus=" + s_valid + ";revokedstatus=" + s_revoked + ";unknownstatus=" + s_unknown;
                buf = Encoding.UTF8.GetBytes(cfg);
            }
            blob.cb = (uint)buf.Length;
            blob.pb = Marshal.AllocCoTaskMem(buf.Length);
            Marshal.Copy(buf, 0, blob.pb, buf.Length);
            return 0;
        }
        catch (Exception ex)
        {
            Log("[revdb] GetConfigInformation failed: " + ex);
            return unchecked((int)0x80004005);
        }
    }

    public int GetProviderManager(out IntPtr pIManager)
    {
        pIManager = IntPtr.Zero;
        try
        {
            if (s_manager == null) s_manager = new OcspDbProviderManager();
            if (s_managerIface == IntPtr.Zero)
                s_managerIface = Marshal.GetComInterfaceForObject(s_manager, typeof(IOCSPRevInfoProviderManager));
            pIManager = s_managerIface;
            return 0;
        }
        catch (Exception ex)
        {
            Log("[revdb] GetProviderManager failed: " + ex.Message);
            return unchecked((int)0x80004005);
        }
    }
}

[ComVisible(true)]
[Guid("C1E7D2A4-5B33-4E7A-A0C6-93E2B7D4F1A8")]
[ClassInterface(ClassInterfaceType.None)]
public sealed class OcspDbProviderManager : IOCSPRevInfoProviderManager
{
    const int E_NOTIMPL = unchecked((int)0x80004001);

    public int GetProviderInformation(out IntPtr pbstrName, out IntPtr pbstrDescription)
    {
        pbstrName = Marshal.StringToBSTR("NAS CA database (no CRL)");
        pbstrDescription = Marshal.StringToBSTR(
            "Revocation status is read from a snapshot of the CA certificate database. No CRL is used.");
        return 0;
    }

    public int Configure(IntPtr hwndParent, string bstrCAConfigId, ref CERTTRANSBLOB pcCACertificate,
                         ref CERTTRANSBLOB pcInConfigInformation, out int pbModified, out CERTTRANSBLOB pOutConfigInformation)
    {
        pbModified = 0;
        pOutConfigInformation = new CERTTRANSBLOB { cb = 0, pb = IntPtr.Zero };
        return E_NOTIMPL;      // 没有 UI：配置直接写注册表 Provider 子键
    }

    public int View(IntPtr hwndParent, string bstrCAConfigId, ref CERTTRANSBLOB pcCACertificate,
                    ref CERTTRANSBLOB pcInConfigInformation)
    {
        return E_NOTIMPL;
    }

    public int GetStatus(string bstrCAConfigId, ref CERTTRANSBLOB pcCACertificate,
                         ref CERTTRANSBLOB pcInConfigInformation, out IntPtr pVarStatus, out int pHRStatus)
    {
        pVarStatus = IntPtr.Zero;
        pHRStatus = 0;
        return E_NOTIMPL;
    }

    public int Initialize(string bstrCAConfigId, ref CERTTRANSBLOB pcCACertificate, out CERTTRANSBLOB pOutConfigInformation)
    {
        pOutConfigInformation = new CERTTRANSBLOB { cb = 0, pb = IntPtr.Zero };
        return E_NOTIMPL;
    }
}

// ---------------------------------------------------------------- 快照同步

public static class RevDbSync
{
    // certutil -view 的记录块里，字段顺序固定：请求ID / 序列号 / 请求处理 / 吊销日期 / 吊销原因 / 过期日期
    // 这里只认"值"不认标签（标签随系统语言变），所以靠形状匹配。
    static readonly System.Text.RegularExpressions.Regex ReQuoted =
        new System.Text.RegularExpressions.Regex("\"([0-9a-fA-F]{6,})\"");
    static readonly System.Text.RegularExpressions.Regex ReDisp =
        new System.Text.RegularExpressions.Regex(@"0x([0-9a-fA-F]+)\s*\((\d+)\)");
    static readonly System.Text.RegularExpressions.Regex ReHexNum =
        new System.Text.RegularExpressions.Regex(@"0x([0-9a-fA-F]+)");
    static readonly System.Text.RegularExpressions.Regex ReDate =
        new System.Text.RegularExpressions.Regex(@"(\d{4})/(\d{1,2})/(\d{1,2})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?");

    static long ToFileTimeUtc(DateTime dt)
    {
        try { return dt.ToUniversalTime().ToFileTimeUtc(); } catch { return 0; }
    }

    static CERTTRANSBLOB Blob(byte[] buf)
    {
        if (buf == null || buf.Length == 0) return new CERTTRANSBLOB { cb = 0, pb = IntPtr.Zero };
        var b = new CERTTRANSBLOB();
        b.cb = (uint)buf.Length;
        b.pb = Marshal.AllocCoTaskMem(buf.Length);
        Marshal.Copy(buf, 0, b.pb, buf.Length);
        return b;
    }

    static RevStatusInfo Ask(IOCSPRevInfoProvider prov, string serialHex)
    {
        var raw = new byte[serialHex.Length / 2];
        for (int i = 0; i < raw.Length; i++)
            raw[i] = byte.Parse(serialHex.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        var blob = Blob(raw);
        RevStatusInfo st;
        int hr = prov.VerifySerialNumber(ref blob, out st);
        if (blob.pb != IntPtr.Zero) Marshal.FreeCoTaskMem(blob.pb);
        Console.WriteLine(string.Format("  serial={0}  hr=0x{1:X8}  status={2}  reason={3}  revokedDate={4}",
            serialHex, hr, st.dwStatus, st.dwRevocationReason,
            st.ftRevocationDate == 0 ? "-" : DateTime.FromFileTimeUtc(st.ftRevocationDate).ToString("u")));
        return st;
    }

    static int SelfTest(string[] args)
    {
        Console.WriteLine("=== provider selftest (through the registered COM class) ===");
        Console.WriteLine("  sizeof(RevStatusInfo)=" + Marshal.SizeOf(typeof(RevStatusInfo)) +
                          " (native expects 40)");
        Console.WriteLine("  offsets: dwStatus=" + Marshal.OffsetOf(typeof(RevStatusInfo), "dwStatus") +
                          " ftThisUpdate=" + Marshal.OffsetOf(typeof(RevStatusInfo), "ftThisUpdate") +
                          " ftNextUpdate=" + Marshal.OffsetOf(typeof(RevStatusInfo), "ftNextUpdate") +
                          " ftRevocationDate=" + Marshal.OffsetOf(typeof(RevStatusInfo), "ftRevocationDate") +
                          " dwRevocationReason=" + Marshal.OffsetOf(typeof(RevStatusInfo), "dwRevocationReason"));
        Console.WriteLine("  sizeof(CERTTRANSBLOB)=" + Marshal.SizeOf(typeof(CERTTRANSBLOB)) + " (native expects 16)");
        try
        {
            var t = Type.GetTypeFromCLSID(new Guid("7B0C4B1E-93A1-4C0F-9E52-0D2A6A5B41C9"));
            var prov = (IOCSPRevInfoProvider)Activator.CreateInstance(t);
            Console.WriteLine("  CoCreateInstance ok");

            var empty = Blob(null);
            int hr = prov.Initialize("CA-NAME", ref empty, ref empty);
            Console.WriteLine("  Initialize hr=0x" + hr.ToString("X8"));

            CERTTRANSBLOB cfg;
            hr = prov.GetConfigInformation(out cfg);
            if (cfg.pb != IntPtr.Zero && cfg.cb > 0)
            {
                var buf = new byte[cfg.cb];
                Marshal.Copy(cfg.pb, buf, 0, (int)cfg.cb);
                Console.WriteLine("  config = " + Encoding.UTF8.GetString(buf));
                Marshal.FreeCoTaskMem(cfg.pb);
            }

            // 数据库里已知的三类：CA 自签、已吊销、随便编的
            Ask(prov, "1BB4C8FDB13FF1AD40B36BB38899571D");
            Ask(prov, "6200000003CC4141256F50414D000000000003");
            Ask(prov, "DEADBEEF00000000000000000000000000000001");
            return 0;
        }
        catch (Exception ex)
        {
            Console.WriteLine("  FAILED: " + ex);
            return 1;
        }
    }

    public static int Run(string[] args)
    {
        if (Array.IndexOf(args, "-Selftest") >= 0) return SelfTest(args);

        string caConfig = "";                 // 空 = 用本机 CA（带 -config 会走 RPC，本机反而失败）
        string outPath = @"C:\ProgramData\OcspDbProvider\revdb.dat";
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "-Config") caConfig = args[i + 1];
            else if (args[i] == "-Out") outPath = args[i + 1];
        }
        string dir = Path.GetDirectoryName(outPath);
        Directory.CreateDirectory(dir);
        string logPath = Path.Combine(dir, "sync.log");

        try
        {
            string cargs = "-view -silent -out \"SerialNumber,Disposition,RevokedWhen,RevokedReason,NotAfter\"";
            if (caConfig.Length > 0 && caConfig != "CA-NAME") cargs = "-view -silent -config \"" + caConfig + "\" -out \"SerialNumber,Disposition,RevokedWhen,RevokedReason,NotAfter\"";
            var psi = new System.Diagnostics.ProcessStartInfo("certutil.exe", cargs)
            {
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage)
            };
            var p = System.Diagnostics.Process.Start(psi);
            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            p.WaitForExit(60000);

            var lines = new List<string>();
            string curSerial = null;
            int curDisp = -1, curReason = 0;
            long curRevoked = 0, curNotAfter = 0;
            bool curSeenDisp = false;

            Action flush = () =>
            {
                if (curSerial != null && curDisp >= 0)
                    lines.Add(curSerial + "\t" + curDisp + "\t" + curRevoked + "\t" + curReason + "\t" + curNotAfter);
                curSerial = null; curDisp = -1; curReason = 0; curRevoked = 0; curNotAfter = 0; curSeenDisp = false;
            };

            foreach (string raw in stdout.Split('\n'))
            {
                string line = raw.TrimEnd('\r');
                var mq = ReQuoted.Match(line);
                if (mq.Success)
                {
                    // 每个"序列号: \"xxxx\"" 就是一条新记录的起点 → 先把上一条落盘
                    flush();
                    curSerial = mq.Groups[1].Value;
                    continue;
                }
                if (curSerial == null) continue;
                if (!curSeenDisp)
                {
                    var md = ReDisp.Match(line);
                    if (md.Success)
                    {
                        curDisp = int.Parse(md.Groups[2].Value, CultureInfo.InvariantCulture);
                        curSeenDisp = true;
                        continue;
                    }
                }
                var mdate = ReDate.Match(line);
                if (mdate.Success)
                {
                    var dt = new DateTime(int.Parse(mdate.Groups[1].Value), int.Parse(mdate.Groups[2].Value),
                                          int.Parse(mdate.Groups[3].Value), int.Parse(mdate.Groups[4].Value),
                                          int.Parse(mdate.Groups[5].Value),
                                          mdate.Groups[6].Success ? int.Parse(mdate.Groups[6].Value) : 0);
                    if (curDisp == 21 && curRevoked == 0) curRevoked = ToFileTimeUtc(dt);
                    else if (curNotAfter == 0) curNotAfter = ToFileTimeUtc(dt);
                    continue;
                }
                var mh = ReHexNum.Match(line);
                if (mh.Success && !ReDisp.IsMatch(line) && curDisp == 21 && curReason == 0)
                {
                    int r;
                    if (int.TryParse(mh.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out r))
                        curReason = r;
                }
            }
            flush();

            // ★ 保护：certutil 失败或解析出 0 条时【不要】用空快照覆盖已有的好快照，
            //   否则一次抖动就会让 OCSP 对所有证书回答 unknown。
            if (lines.Count == 0 || p.ExitCode != 0)
            {
                File.AppendAllText(logPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") +
                                            "  sync kept old snapshot rows=" + lines.Count +
                                            " exit=" + p.ExitCode + "\r\n", Encoding.UTF8);
                return 2;
            }

            string tmp = outPath + ".tmp";
            var sb = new StringBuilder();
            sb.AppendLine("# NasOcsp revdb snapshot  generated " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") +
                          "  from CA " + (caConfig.Length == 0 ? "(local)" : caConfig) + "  rows=" + lines.Count);
            foreach (string l in lines) sb.AppendLine(l);
            File.WriteAllText(tmp, sb.ToString(), new UTF8Encoding(false));
            if (File.Exists(outPath)) File.Delete(outPath);
            File.Move(tmp, outPath);

            File.AppendAllText(logPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  sync ok rows=" +
                                        lines.Count + " exit=" + p.ExitCode + "\r\n", Encoding.UTF8);
            return 0;
        }
        catch (Exception ex)
        {
            try
            {
                File.AppendAllText(logPath, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  sync FAILED " +
                                            ex.Message + "\r\n", Encoding.UTF8);
            }
            catch { }
            return 1;
        }
    }
}

