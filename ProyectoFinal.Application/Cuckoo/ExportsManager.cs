using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class ExportsManager: GenericManager<Exports>, IExportsManager
    {
        /// <summary>
        /// constructor de exports manager
        /// </summary>
        /// <param name="context"></param>
        public ExportsManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
