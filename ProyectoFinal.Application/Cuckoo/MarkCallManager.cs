using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class MarkCallManager: GenericManager<MarkCall>, IMarkCallManager
    {
        /// <summary>
        /// Constructor de MarkCallManager
        /// </summary>
        /// <param name="context"></param>
        public MarkCallManager(IApplicationDbContext context):base(context)
        {
        }
    }
}
