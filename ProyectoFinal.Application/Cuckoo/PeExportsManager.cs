using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class PeExportsManager: GenericManager<PeExport>, IPeExportsManager
    {
        /// <summary>
        /// constructor de pe exports manager
        /// </summary>
        /// <param name="context"></param>
        public PeExportsManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
