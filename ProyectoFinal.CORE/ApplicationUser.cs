using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace ProyectoFinal.CORE
{
    public class ApplicationUser : IdentityUser
    {
        ///// <summary>
        ///// Imagen del Avatar del usuario
        ///// </summary>
        //public string Avatar { get; set; }

        ///// <summary>
        ///// Descripcion del usuario
        ///// </summary>
        //public string Descripcion { get; set; }

        ///// <summary>
        ///// Twitter del usuario
        ///// </summary>
        //public string? Twitter { get; set; }

        ///// <summary>
        ///// Github del usuario
        ///// </summary>
        //public string? GitHub { get; set; }

        ///// <summary>
        ///// Facebook del usuario
        ///// </summary>
        //public string? Facebook { get; set; }

        ///// <summary>
        ///// Instagram del usuario
        ///// </summary>
        //public string? Instagram { get; set; }
        public virtual List<Malware> Malwares { get; set; }
        public virtual List<Comment> Comments { get; set; }

    }
}