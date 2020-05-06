using System;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.Application.Cuckoo
{
    public class StaticKeysManager: GenericManager<StaticKeys>, IStaticKeysManager
    {
        /// <summary>
        /// constructor de static keys maanger
        /// </summary>
        /// <param name="context"></param>
        public StaticKeysManager(IApplicationDbContext context):base(context)
        {
        }
    }
}
