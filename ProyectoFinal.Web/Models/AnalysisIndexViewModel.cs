using System;
using System.Collections.Generic;
using ProyectoFinal.CORE;

namespace ProyectoFinal.Web.Models
{
    public class AnalysisIndexViewModel
    {
            public Malware Malware { get; set; }
            public List<ScreenShot> Screenshots { get; set; }
            public List<Comment> Comments { get; set; }
            public AnalysisResultViewModel Result { get; set; }
    }
}
