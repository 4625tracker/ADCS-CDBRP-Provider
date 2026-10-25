// RevDbSync.exe 只是个薄壳：逻辑都在 OcspDbProvider.dll 里，
// 这样 -Selftest 创建的 COM 对象和接口类型都来自同一个程序集，cast 才成立。
public static class Program
{
    public static int Main(string[] args)
    {
        return RevDbSync.Run(args);
    }
}
