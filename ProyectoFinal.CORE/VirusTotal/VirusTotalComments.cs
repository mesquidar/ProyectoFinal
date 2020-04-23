using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.VirusTotal
{
    public class VirusTotalComments
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
        /// fecha del comentario
        /// </summary>
        public DateTime Date { get; set; }

        /// <summary>
        /// comentario 
        /// </summary>
        public string Comment { get; set; }
    }
}
