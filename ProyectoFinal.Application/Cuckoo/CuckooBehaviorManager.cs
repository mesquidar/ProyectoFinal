using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class CuckooBehaviorManager: GenericManager<CuckooBehavior>, ICuckooBehaviorManager
    {
        /// <summary>
        /// constructor de cuckoo behavior manager
        /// </summary>
        /// <param name="context"></param>
        public CuckooBehaviorManager(IApplicationDbContext context):base(context)
        {
        }
    }
}
