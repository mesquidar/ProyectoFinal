using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using ProyectoFinal.CORE.ThreatCrowd;

namespace ProyectoFinal.Application.ThreatCrowd
{
    public class TCReferencesManager: GenericManager<TCReferences>, ITCReferencesManager
    {
        /// <summary>
        /// constructor tcreferences manager
        /// </summary>
        /// <param name="context"></param>
        public TCReferencesManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
