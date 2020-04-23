using Microsoft.AspNetCore.Identity;

namespace ProyectoFinal.CORE
{
    public class ApplicationUser : IdentityUser
    {
        /// <summary>
        /// Twitter del usuario
        /// </summary>
        public string? Twitter { get; set; }

        /// <summary>
        /// Github del usuario
        /// </summary>
        public string? GitHub { get; set; }

        /// <summary>
        /// Facebook del usuario
        /// </summary>
        public string? Facebook { get; set; }

        /// <summary>
        /// Instagram del usuario
        /// </summary>
        public string? Instagram { get; set; }

    }
}