using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class TargetUrls
    {

        public int Id { get; set; }

        public int Target_Id { get; set; }

        public virtual CuckooTarget CuckooTarget { get; set; }

        public string Url { get; set; }
    }
}
