
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.DAL;

namespace ProyectoFinal.Application
{
    public class RoleManager : GenericManager<IdentityRole>, IRoleManager
    {
        /// <summary>
        /// constructor de RoleManager
        /// </summary>
        /// <param name="context">contexto de datos</param>
        public RoleManager(IApplicationDbContext context) : base(context)
        {
        }
    }
}

