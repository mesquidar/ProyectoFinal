using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class DroppedUrlsManager:GenericManager<DroppedUrls>, IDroppedUrlsManager
    {
        /// <summary>
        /// constuctor de dropped urls manager
        /// </summary>
        /// <param name="context"></param>
        public DroppedUrlsManager(IApplicationDbContext context):base(context)
        {
        }
    }
}
