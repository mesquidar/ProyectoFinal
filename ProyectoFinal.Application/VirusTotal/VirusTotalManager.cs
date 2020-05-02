using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.VirusTotal;
using ProyectoFinal.CORE.VirusTotal;

namespace ProyectoFinal.Application.VirusTotal
{
    public class VirusTotalManager: GenericManager<VirusTotalInfo>, IVirusTotalManager
    {
        /// <summary>
        /// Constructor de virus total manager
        /// </summary>
        /// <param name="context"></param>
        public VirusTotalManager(IApplicationDbContext context) : base(context)
        {
        }
    }
}
