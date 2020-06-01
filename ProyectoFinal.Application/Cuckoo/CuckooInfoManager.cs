using System;
using ProyectoFinal.CORE.Cuckoo;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Contracts;
using System.Linq;

namespace ProyectoFinal.Application.Cuckoo
{
    public class CuckooInfoManager: GenericManager<CuckooInfo>, ICuckooInfoManager
    {
        /// <summary>
        /// Constructor de CuckooInfoManager
        /// </summary>
        /// <param name="context"></param>
        public CuckooInfoManager(IApplicationDbContext context) : base(context)
        {
        }

        /// <summary>
        /// Metodo que obtiene cuckooinfo mediante el id de malware
        /// </summary>
        /// <param name="id">id de malware</param>
        /// <returns></returns>
        public CuckooInfo GetByMalwareId(int id)
        {
            return Context.Set<CuckooInfo>().Where(e => e.Malware_Id == id).FirstOrDefault();
        }
    }
}
