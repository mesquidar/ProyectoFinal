using System;
using ProyectoFinal.CORE.Cuckoo;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Contracts;

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
    }
}
