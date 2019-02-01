#undef TRACE
using System;
using DokanNet;
using System.Collections.Generic;
using System.IO;
using DokanNet.Logging;
namespace Dokany_WinUnionFs
{
    class Program
    {
        public static RWPerm fromstr(string str)
        {
            if (str.ToUpper().Equals("RW"))
            {
                return RWPerm.RW;
            } else
            {
                return RWPerm.RO;
            }
        }
        static List<FS> lfs = new List<FS>();
        static void Main(string[] args)
        {
            Console.WriteLine(args[0]);
            String CD = Directory.GetCurrentDirectory();
            String[] fs = args[0].Split(';');
            foreach(string dir in fs)
            {
                FS tln = new FS();
                string[] d = dir.Split('=');
                tln.TLD = Path.Combine(CD, d[0]);
                if (d.Length == 2)
                {
                    tln.P = fromstr(d[1]);
                } else
                {
                    tln.P = RWPerm.RO;
                }
                Console.WriteLine(tln.P.ToString());
                lfs.Add(tln);
            }
            WinUnion wu = new WinUnion(lfs);
            DokanOptions opt = DokanOptions.DebugMode;
            Dokan.Mount(wu, args[1], opt, new NullLogger());
        }
    }
}
