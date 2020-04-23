using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.ThreatCrowd
{
    public class ThreatCrowd
    {
        /// <summary>
        /// Id de la busqueda de ThreatCrowd
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
        /// Tipo de busqueda
        /// </summary>
        public string Type { get; set; }

        /// <summary>
        /// Lista de TCResolutions
        /// </summary>
        public List<TCResolution> TCResolutions { get; set; }

        /// <summary>
        /// Lista de hashes
        /// </summary>
        public List<string> Hashes { get; set; }

        /// <summary>
        /// Lista de emails
        /// </summary>
        public List<string> Emails { get; set; }

        /// <summary>
        /// Lista de dominios
        /// </summary>
        public List<string> Domains { get; set; }

        /// <summary>
        /// Lista de subdominios
        /// </summary>
        public List<string> Subdomains { get; set; }

        /// <summary>
        /// Lista de referencias
        /// </summary>
        public List<string> References { get; set; }

        /// <summary>
        /// Lista de scans
        /// </summary>
        public List<string> Scans { get; set; }

        /// <summary>
        /// Lista de ips
        /// </summary>
        public List<string> Ips { get; set; }

        /// <summary>
        /// Votos en ThreatCrowd
        /// </summary>
        public int Votes { get; set; }

        /// <summary>
        /// Link permanente en ThreatCrowd
        /// </summary>
        public string Permalink { get; set; }
    }
}
