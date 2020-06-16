using System;
using System.Collections.Generic;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Web.Models
{
    public class AnalysisCuckooViewModel
    {
        public Malware Malware { get; set; }
        public CuckooTarget CuckooTarget { get; set; }
        public CuckooInfo CuckooInfo { get; set; }
        public List<CuckooSignature> Signatures { get; set; }
        public AnalysisCuckooStaticViewModel CuckooStaticViewModel { get; set; }
        public AnalysisCuckooDroppedViewModel CuckooDroppedViewModel { get; set; }
        public AnalysisCuckooTargetViewModel CuckooTargetViewModel { get; set; }
        public AnalysisCuckooBehaviorViewModel CuckooBehaviorViewModel { get; set; }
    }
}
