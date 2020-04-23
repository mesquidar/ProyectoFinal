using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.VirusTotal
{
    public class VirusTotal
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
        public Dictionary<string, VirusTotalScans> Scans{ get; set; }

        /// <summary>
        /// Escano de virustotal
        /// </summary>
        public virtual VirusTotalScans Scan { get; set; }

        /// <summary>
        /// Lista de los comentario de virus total
        /// </summary>
        public List<VirusTotalComments> Comments { get; set; }

        /// <summary>
        /// Comentarios de virustotal
        /// </summary>
        public virtual VirusTotalComments VirusTotalComments { get; set; }

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
