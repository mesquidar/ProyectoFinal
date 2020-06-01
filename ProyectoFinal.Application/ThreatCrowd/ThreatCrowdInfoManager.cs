using System;
using System.Linq;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using ProyectoFinal.CORE.ThreatCrowd;

namespace ProyectoFinal.Application.ThreatCrowd
{
    public class ThreatCrowdInfoManager: GenericManager<ThreatCrowdInfo>, IThreatCrowdInfoManager
    {
        /// <summary>
        /// constructor de threatcrowdinfo manager
        /// </summary>
        /// <param name="context"></param>
        public ThreatCrowdInfoManager(IApplicationDbContext context): base(context)
        {
        }

        /// <summary>
        /// Metodo que obtiene threatcrowdinfo mediante el id de malware
        /// </summary>
        /// <param name="id">id de malware</param>
        /// <returns><ThreatCropwdInfo/returns>
        public ThreatCrowdInfo GetByMalwareId(int id)
        {
            return Context.Set<ThreatCrowdInfo>().Where(e => e.Malware_Id == id).FirstOrDefault();
        }
    }
}
