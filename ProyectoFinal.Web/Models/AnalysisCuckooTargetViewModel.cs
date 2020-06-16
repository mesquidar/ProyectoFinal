using System;
using System.Collections.Generic;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Web.Models
{
    public class AnalysisCuckooTargetViewModel
    {
        public CuckooTarget CuckooTarget { get; set; }
        public List<TargetPids> TargetPids { get; set; }
        public List<TargetUrls> Targeturls { get; set; }
    }
}
