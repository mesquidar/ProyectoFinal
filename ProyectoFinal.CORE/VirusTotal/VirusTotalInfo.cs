using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.VirusTotal
{
    public class VirusTotalInfo
    {
        /// <summary>
        /// Id del analisis de virustotal
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Id del malware asociado
        /// </summary>
        public int Malware_Id { get; set; }

        /// <summary>
        /// Malware asociado
        /// </summary>
        public virtual Malware Malware { get; set; }

        /// <summary>
        /// Escaneo de los distintos antivurs de virustotal
        /// </summary>
        public List<VirusTotalScans> Scans{ get; set; }

        /// <summary>
        /// Lista de los comentario de virus total
        /// </summary>
        public List<VirusTotalComments> Comments { get; set; }

        /// <summary>
        /// Total de analisis realizados
        /// </summary>
        public int Total { get; set; }

        /// <summary>
        /// Analisis positivos
        /// </summary>
        public int Positives { get; set; }
    }
}
