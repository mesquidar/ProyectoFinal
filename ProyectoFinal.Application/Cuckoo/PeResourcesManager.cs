using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class PeResourcesManager: GenericManager<PeResource>, IPeResourcesManager
    {
        /// <summary>
        /// constructor de pe resources manager
        /// </summary>
        /// <param name="context"></param>
        public PeResourcesManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
