using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class YaraDroppedManager: GenericManager<YaraDropped>, IYaraDroppedManager
    {
        /// <summary>
        /// /Constructor de YaraDropped Manager
        /// </summary>
        /// <param name="context"></param>
        public YaraDroppedManager(IApplicationDbContext context): base(context)
        {
        }
    }
}
