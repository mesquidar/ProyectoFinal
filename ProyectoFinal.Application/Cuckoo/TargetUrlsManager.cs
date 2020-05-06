using System;
using ProyectoFinal.CORE.Cuckoo;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class TargetUrlsManager : GenericManager<TargetUrls>, ITargetUrlsManager
    {
        /// <summary>
        /// Constructor de TargetUrlsManager
        /// </summary>
        /// <param name="context"></param>
        public TargetUrlsManager(IApplicationDbContext context) : base(context)
        {
        }
    }
}