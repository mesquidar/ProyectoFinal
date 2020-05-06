using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class BehaviorSummaryManager:GenericManager<BehaviorSummary>, IBehaviorSummaryManager
    {
        /// <summary>
        /// constructor de behavior summary manager
        /// </summary>
        /// <param name="context"></param>
        public BehaviorSummaryManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
