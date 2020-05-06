using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class StaticSignaturesManager: GenericManager<StaticSignature>, IStaticSignaturesManager
    {
        /// <summary>
        /// Constructor de static signaures manager
        /// </summary>
        /// <param name="context"></param>
        public StaticSignaturesManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
