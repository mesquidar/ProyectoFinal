using System;
using System.Collections.Generic;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Web.Models
{
    public class AnalysisCuckooBehaviorViewModel
    {
        public CuckooBehavior CuckooBehavior { get; set; }
        public List<BehaviorSummary> BehaviorSummary { get; set; }
        public List<ProcessTree> ProcessTree { get; set; }
    }
}
