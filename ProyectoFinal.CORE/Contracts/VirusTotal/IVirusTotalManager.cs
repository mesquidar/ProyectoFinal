using System;
using ProyectoFinal.CORE.VirusTotal;

namespace ProyectoFinal.CORE.Contracts.VirusTotal
{
    public interface IVirusTotalManager: IGenericManager<VirusTotalInfo>
    {
        VirusTotalInfo GetByMalwareId(int id);
    }
}
