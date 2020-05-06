using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class ProcessTreeManager: GenericManager<ProcessTree>, IProcessTreeManager
    {
        /// <summary>
        /// constructor de processtree manger
        /// </summary>
        /// <param name="context"></param>
        public ProcessTreeManager(IApplicationDbContext context):base(context)
        {
        }
    }
}
