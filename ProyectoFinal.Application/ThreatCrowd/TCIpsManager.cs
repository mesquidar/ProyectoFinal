using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using ProyectoFinal.CORE.ThreatCrowd;

namespace ProyectoFinal.Application.ThreatCrowd
{
    public class TCIpsManager: GenericManager<TCIps>, ITCIpsManager
    {
        /// <summary>
        /// constructor de tc ips manager
        /// </summary>
        /// <param name="context"></param>
        public TCIpsManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
