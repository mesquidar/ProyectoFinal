using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using ProyectoFinal.CORE.ThreatCrowd;

namespace ProyectoFinal.Application.ThreatCrowd
{
    public class TCResolutionManager: GenericManager<TCResolution>, ITCResolutionManager
    {
        /// <summary>
        /// constructor de tc resolutions manager
        /// </summary>
        /// <param name="context"></param>
        public TCResolutionManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
