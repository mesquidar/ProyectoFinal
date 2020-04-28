using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace ProyectoFinal.Web.Areas.Admin.Models
{
    public class UserEdit
    {
                /// <summary>
                /// lista de usuarios
                /// </summary>
                public UserList User { get; set; }
                /// <summary>
                /// lista de rol
                /// </summary>
                public RolList Rol { get; set; }
                /// <summary>
                /// opcion seleccionada
                /// </summary>
                public string Option { get; set; }
        
                public IList<SelectListItem> ItemList { get; set; }
    }
}