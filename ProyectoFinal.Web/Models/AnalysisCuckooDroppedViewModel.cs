using System;
using System.Collections.Generic;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Web.Models
{
    public class AnalysisCuckooDroppedViewModel
    {
        public List<CuckooDropped> CuckooDropped { get; set; }
        public List<DroppedPids> DroppedPids { get; set; }
        public List<DroppedUrls> DroppedUrls { get; set; }
        public List<YaraDropped> YaraDropped { get; set; }
    }
}
