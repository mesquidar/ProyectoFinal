using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class DroppedUrls
    {
        public int Id { get; set; }
        public virtual CuckooDropped CuckooDropped { get; set; }
        [ForeignKey("CuckoDropped")]
        public int Dropped_Id { get; set; }       
        public string Url { get; set; }
    }
}
