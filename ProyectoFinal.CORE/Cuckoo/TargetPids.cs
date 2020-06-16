using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class TargetPids
    {
        public int Id { get; set; }

        [ForeignKey("Target_Id")]
        public virtual CuckooTarget CuckooTarget { get; set; }

        
        public int Target_Id { get; set; }
        
        public int Pid { get; set; }
    }
}
