using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class MarkSectionManager: GenericManager<MarkSection>, IMarkSectionManager
    {
        /// <summary>
        /// constructor de mark section manager
        /// </summary>
        /// <param name="context"></param>
        public MarkSectionManager(IApplicationDbContext context):base(context)
        {
        }
    }
}
