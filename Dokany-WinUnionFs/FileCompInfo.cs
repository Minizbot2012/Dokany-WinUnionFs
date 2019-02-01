using DokanNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Dokany_WinUnionFs
{
    class FileCompInfo : IEqualityComparer<FileInformation>
    {
        public bool Equals(FileInformation x, FileInformation y)
        {
            return x.FileName.ToLower().Equals(y.FileName.ToLower());
        }

        public int GetHashCode(FileInformation obj)
        {
            return obj.FileName.ToLower().GetHashCode();
        }
    }
}
