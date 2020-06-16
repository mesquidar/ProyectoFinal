using System;
using System.Collections.Generic;
using ProyectoFinal.CORE;

namespace ProyectoFinal.Web.Areas.Admin.Models
{
    public class AdminPanelViewModel
    {
        public List<Malware> Malware { get; set; }
        public List<ScreenShot> ScreenShot { get; set; }
        public List<ApplicationUser> User { get; set; }
        public List<Comment> Comment { get; set; }
    }
}
