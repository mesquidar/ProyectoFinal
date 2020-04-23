using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.VirusTotal
{
    public class VirusTotalScans
    {
        /// <summary>
        /// Id del comentario de virustotal
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// id del analisis de virustotal asociado
        /// </summary>
        public int VirusTotal_Id { get; set; }

        /// <summary>
        /// analisis de virustotal
        /// </summary>
        public virtual VirusTotal VirusTotal { get; set; }

        /// <summary>
        /// Dteccion del malware si es positivo o no
        /// </summary>
        public bool Detected { get; set; }

        /// <summary>
        /// Resultado del analisis
        /// </summary>
        public string Result { get; set; }

        /// <summary>
        /// Version del antivirus 
        /// </summary>
        public string Version { get; set; }

    }
}
