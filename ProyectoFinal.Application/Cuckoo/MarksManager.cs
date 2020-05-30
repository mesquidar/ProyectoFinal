using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class MarksManager: GenericManager<Mark>, IMarksManager
    {
        /// <summary>
        /// constructor de marks manager
        /// </summary>
        /// <param name="context"></param>
        public MarksManager(IApplicationDbContext context):base(context)
        {
        }
    }
}
