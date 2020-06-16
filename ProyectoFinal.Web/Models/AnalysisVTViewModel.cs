using System;
using System.Collections.Generic;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.VirusTotal;

namespace ProyectoFinal.Web.Models
{
    public class AnalysisVTViewModel
    {
        public Malware Malware { get; set; }
        public VirusTotalInfo VTInfo { get; set; }
        public List<VirusTotalScans> VTScans { get; set; }
    }
}
