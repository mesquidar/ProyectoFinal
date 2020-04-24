using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class TargetPids
    {
        public int Id { get; set; }
        public int Target_Id { get; set; }
        public virtual CuckooTarget CuckooTarget { get; set; }
        public int Pid { get; set; }
    }
}
