using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class CuckooDroppedManager: GenericManager<CuckooDropped>, ICuckooDroppedManager
    {
        /// <summary>
        /// Constructor de cuckoo dropped manager
        /// </summary>
        /// <param name="context"></param>
        public CuckooDroppedManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
