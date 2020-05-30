using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using ProyectoFinal.CORE.ThreatCrowd;

namespace ProyectoFinal.Application.ThreatCrowd
{
    public class ThreatCrowdInfoManager: GenericManager<ThreatCrowdInfo>, IThreatCrowdInfoManager
    {
        /// <summary>
        /// constructor de threatcrowdinfo manager
        /// </summary>
        /// <param name="context"></param>
        public ThreatCrowdInfoManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
