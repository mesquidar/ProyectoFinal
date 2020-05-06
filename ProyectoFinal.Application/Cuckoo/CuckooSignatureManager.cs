using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class CuckooSignatureManager: GenericManager<CuckooSignature>, ICuckooSigantureManager
    {
        /// <summary>
        /// constructor de cuckoo signature manager
        /// </summary>
        /// <param name="context"></param>
        public CuckooSignatureManager(IApplicationDbContext context):base(context)
        {
        }
    }
}
