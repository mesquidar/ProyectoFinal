using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class CuckooTargetManager: GenericManager<CuckooTarget>, ICuckooTargetManager
    {
        /// <summary>
        /// Constructor de Cuckoo target manager
        /// </summary>
        /// <param name="context"></param>
        public CuckooTargetManager(IApplicationDbContext context) : base(context)
        {
        }
    }
}
