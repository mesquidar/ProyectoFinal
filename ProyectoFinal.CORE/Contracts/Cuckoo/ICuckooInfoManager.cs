using System;
using ProyectoFinal.CORE.Cuckoo;

namespace ProyectoFinal.CORE.Contracts.Cuckoo
{
    public interface ICuckooInfoManager: IGenericManager<CuckooInfo>
    {
        CuckooInfo GetByMalwareId(int id);
    }
}
