using System;
using System.Collections.Generic;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Cuckoo;
using ProyectoFinal.CORE.ThreatCrowd;
using ProyectoFinal.CORE.VirusTotal;

namespace ProyectoFinal.Web.Models
{
    public class AnalysisIndexViewModel
    {
            public Malware Malware { get; set; }
            public List<ScreenShot> Screenshots { get; set; }
            public List<Comment> Comments { get; set; }
            public VirusTotalInfo VTInfo { get; set; }
            public CuckooInfo CuckooInfo { get; set; }
            public ThreatCrowdInfo TCInfo { get; set; }
}
}
