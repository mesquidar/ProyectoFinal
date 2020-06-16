using System;
using System.Collections.Generic;
using System.Linq;
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

        /// <summary>
        /// Metodo que obtiene virustotalinfo mediante el id de malware
        /// </summary>
        /// <param name="id">id de malware</param>
        /// <returns><ThreatCropwdInfo/returns>
        public List<VirusTotalScans> GetByVTId(int id)
        {
            return Context.Set<VirusTotalScans>().Where(e => e.VirusTotal_Id == id).ToList();
        }
    }
}
