using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.ThreatCrowd
{
    public class ThreatCrowdInfo
    {
        /// <summary>
        /// Id de la busqueda de ThreatCrowd
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Malware asociado
        /// </summary>
        public virtual Malware Malware { get; set; }

        /// <summary>
        /// Id del malware asociado
        /// </summary>
        [ForeignKey("Malware")]
        public int Malware_Id { get; set; }

        /// <summary>
        /// Tipo de busqueda
        /// </summary>
        public string Type { get; set; }

        /// <summary>
        /// Lista de TCResolutions
        /// </summary>
        public virtual List<TCResolution> TCResolutions { get; set; }

        /// <summary>
        /// Lista de hashes
        /// </summary>
        public virtual List<TCHashes> Hashes { get; set; }

        /// <summary>
        /// Lista de emails
        /// </summary>
        public virtual List<TCEmails> Emails { get; set; }

        /// <summary>
        /// Lista de dominios
        /// </summary>
        public virtual List<TCDomains> Domains { get; set; }

        /// <summary>
        /// Lista de subdominios
        /// </summary>
        public virtual List<TCSubdomanins> Subdomains { get; set; }

        /// <summary>
        /// Lista de referencias
        /// </summary>
        public virtual List<TCReferences> References { get; set; }

        /// <summary>
        /// Lista de scans
        /// </summary>
        public virtual List<TCScans> Scans { get; set; }

        /// <summary>
        /// Lista de ips
        /// </summary>
        public virtual List<TCIps> Ips { get; set; }

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
