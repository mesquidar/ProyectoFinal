using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using ProyectoFinal.CORE.ThreatCrowd;

namespace ProyectoFinal.Application.ThreatCrowd
{
    public class TCEmailsManager: GenericManager<TCEmails>, ITCEmailsManager
    {
        /// <summary>
        /// constructor de tcemails manager
        /// </summary>
        /// <param name="context"></param>
        public TCEmailsManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
