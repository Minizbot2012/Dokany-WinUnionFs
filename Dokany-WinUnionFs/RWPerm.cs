using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Dokany_WinUnionFs
{
    public struct FS {
        public RWPerm P;
        public String TLD;
    }
    public enum RWPerm { RW, RO };
}