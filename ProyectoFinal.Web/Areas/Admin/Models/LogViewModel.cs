using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace ProyectoFinal.Web.Areas.Admin.Models
{
    public class LogViewModel
    {
        public IList<SelectListItem> Log { get; set; }
        public string Option { get; set; }
    }
}
