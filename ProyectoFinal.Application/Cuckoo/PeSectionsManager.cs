using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class PeSectionsManager: GenericManager<PeSection>, IPeSectionsManager
    {
        /// <summary>
        /// constructor de pe sections manager
        /// </summary>
        /// <param name="context"></param>
        public PeSectionsManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
