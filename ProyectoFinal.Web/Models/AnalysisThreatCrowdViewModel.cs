using System;
using System.Collections.Generic;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.ThreatCrowd;

namespace ProyectoFinal.Web.Models
{
    public class AnalysisThreatCrowdViewModel
    {
        public Malware Malware { get; set; }
        public ThreatCrowdInfo TCInfo { get; set; }
        public List<TCScans> TCScans { get; set; }
        public List<TCIps> TCIps { get; set; }
        public List<TCDomains>TCDomains { get; set; }
        public List<TCEmails> TCEmails { get; set; }
        public List<TCHashes> TCHashes { get; set; }
        public List<TCSubdomanins> TCSubdomanins { get; set; }
        public List<TCReferences> TCReferences { get; set; }
        public List<TCResolution> TCResolutions { get; set; }
    }
}
