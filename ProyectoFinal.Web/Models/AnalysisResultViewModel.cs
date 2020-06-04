using System;
using ProyectoFinal.CORE.Cuckoo;
using ProyectoFinal.CORE.ThreatCrowd;
using ProyectoFinal.CORE.VirusTotal;

namespace ProyectoFinal.Web.Models
{
    public class AnalysisResultViewModel
    {

            public VirusTotalInfo VTInfo { get; set; }
            public CuckooInfo CuckooInfo { get; set; }
            public ThreatCrowdInfo TCInfo { get; set; }

     }
}


