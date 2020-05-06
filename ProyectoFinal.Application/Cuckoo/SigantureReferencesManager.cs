using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class SigantureReferencesManager: GenericManager<SignatureReferences>, ISignatureReferencesManager
    {
        /// <summary>
        /// constructor de signature references manager
        /// </summary>
        /// <param name="context"></param>
        public SigantureReferencesManager(IApplicationDbContext context):base(context)
        {
        }
    }
}
