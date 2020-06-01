using System;
using System.Linq;
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

        /// <summary>
        /// Metodo que obtiene virustotalinfo mediante el id de malware
        /// </summary>
        /// <param name="id">id de malware</param>
        /// <returns><ThreatCropwdInfo/returns>
        public VirusTotalInfo GetByMalwareId(int id)
        {
            return Context.Set<VirusTotalInfo>().Where(e => e.Malware_Id == id).FirstOrDefault();
        }
    }
}
