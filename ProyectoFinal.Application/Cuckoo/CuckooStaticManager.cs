using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class CuckooStaticManager: GenericManager<CuckooStatic>, ICuckooStaticManager
    {
        /// <summary>
        /// constructor de cuckoo static manager
        /// </summary>
        /// <param name="context"></param>
        public CuckooStaticManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
