using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using ProyectoFinal.CORE.ThreatCrowd;

namespace ProyectoFinal.Application.ThreatCrowd
{
    public class TCDomainsManager: GenericManager<TCDomains>, ITCDomainsManager
    {
        /// <summary>
        /// cosntructor de tcdomains manager
        /// </summary>
        /// <param name="context"></param>
        public TCDomainsManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
