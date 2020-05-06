using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class ImportsManager: GenericManager<Imports>, IImportsManager
    {
        /// <summary>
        /// Constructor de imports manager
        /// </summary>
        /// <param name="context"></param>
        public ImportsManager(IApplicationDbContext context):base(context)
        {
        }
    }
}
