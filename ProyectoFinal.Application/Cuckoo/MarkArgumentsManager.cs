using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class MarkArgumentsManager: GenericManager<MarkArguments>, IMarkArgumentsManager
    {
        /// <summary>
        /// constructor de mark arguments manager
        /// </summary>
        /// <param name="context"></param>
        public MarkArgumentsManager(IApplicationDbContext context):base(context)
        {
        }
    }
}
