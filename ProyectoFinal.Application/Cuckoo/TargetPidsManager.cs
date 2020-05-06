using System;
using ProyectoFinal.CORE.Cuckoo;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class TargetPidsManager: GenericManager<TargetPids>, ITargetPidsManager
    {
        /// <summary>
        /// Constructor de TargetPidsManager
        /// </summary>
        /// <param name="context"></param>
        public TargetPidsManager(IApplicationDbContext context) : base(context)
        {
        }
    }
}
