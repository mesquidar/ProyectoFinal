using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc.Rendering;
using ProyectoFinal.CORE;

namespace ProyectoFinal.Web.Areas.Admin.Models
{
    public class ScreenShotEditViewModel
    {
        public IList<SelectListItem> Malware { get; set; }
        public ScreenShot ScreenShot { get; set; }

    }
}
