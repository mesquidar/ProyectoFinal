using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using ProyectoFinal.CORE.ThreatCrowd;

namespace ProyectoFinal.Application.ThreatCrowd
{
    public class TCHashesManager: GenericManager<TCHashes>, ITCHashesManager
    {
        /// <summary>
        /// constructor de tc hashes manager
        /// </summary>
        /// <param name="context"></param>
        public TCHashesManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
