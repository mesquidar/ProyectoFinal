using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class DroppedPids
    {
        public int Id { get; set; }

        public virtual CuckooDropped CuckooDropped { get; set; }

        [ForeignKey("CuckooDropped")]
        public int Dropped_Id { get; set; }
        
        public int Pid { get; set; }
    }
}
