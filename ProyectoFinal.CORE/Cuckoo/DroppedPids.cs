using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class DroppedPids
    {
        public int Id { get; set; }
        public int Dropped_Id { get; set; }
        public virtual CuckooDropped CuckooDropped { get; set; }
        public int Pid { get; set; }
    }
}
