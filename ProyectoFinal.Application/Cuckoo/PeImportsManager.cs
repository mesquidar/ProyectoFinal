using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class PeImportsManager: GenericManager<PeImport>, IPeImportsManager
    {
        /// <summary>
        /// constructor de pe imports manager
        /// </summary>
        /// <param name="context"></param>
        public PeImportsManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
