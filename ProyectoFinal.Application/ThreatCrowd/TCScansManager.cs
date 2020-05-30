using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using ProyectoFinal.CORE.ThreatCrowd;

namespace ProyectoFinal.Application.ThreatCrowd
{
    public class TCScansManager: GenericManager<TCScans>, ITCScansManager
    {
        /// <summary>
        /// constructor de tc scans manager
        /// </summary>
        /// <param name="context"></param>
        public TCScansManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
