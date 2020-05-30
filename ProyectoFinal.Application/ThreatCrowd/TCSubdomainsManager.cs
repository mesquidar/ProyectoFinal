using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using ProyectoFinal.CORE.ThreatCrowd;

namespace ProyectoFinal.Application.ThreatCrowd
{
    public class TCSubdomainsManager: GenericManager<TCSubdomanins>, ITCSubdomainsManager
    {
        /// <summary>
        /// constructor de tcsubdomains manager
        /// </summary>
        /// <param name="context"></param>
        public TCSubdomainsManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
