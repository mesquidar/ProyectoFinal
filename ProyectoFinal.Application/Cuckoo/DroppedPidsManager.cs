using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class DroppedPidsManager:GenericManager<DroppedPids>, IDroppedPidsManager
    {
        /// <summary>
        /// constructor de dropped pids amanger
        /// </summary>
        /// <param name="context"></param>
        public DroppedPidsManager(IApplicationDbContext context):base(context)
        {
        }
    }
}
