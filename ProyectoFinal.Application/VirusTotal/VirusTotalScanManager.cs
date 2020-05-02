using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.VirusTotal;
using ProyectoFinal.CORE.VirusTotal;

namespace ProyectoFinal.Application.VirusTotal
{
    public class VirusTotalScanManager: GenericManager<VirusTotalScans>, IVirusTotalScanManager
    {
        /// <summary>
        /// Constructor de virus total scans manager
        /// </summary>
        /// <param name="context"></param>
        public VirusTotalScanManager(IApplicationDbContext context) : base(context)
        {
        }
    }
}
