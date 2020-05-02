using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.VirusTotal;
using ProyectoFinal.CORE.VirusTotal;

namespace ProyectoFinal.Application.VirusTotal
{
    public class VirusTotalCommentManager: GenericManager<VirusTotalComments>, IVirusTotalCommentManager
    {
        /// <summary>
        /// Constructor de virus total comments manager
        /// </summary>
        /// <param name="context"></param>
        public VirusTotalCommentManager(IApplicationDbContext context) : base(context)
        {
        }
    }
}
