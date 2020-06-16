using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class CuckooSignature
    {
        /// <summary>
        /// id de cuckoo siganture
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// malware asociado
        /// </summary>
        [ForeignKey("CuckooScanId")]
        public virtual CuckooInfo CuckooInfo { get; set; }

        /// <summary>
        /// id de malware asociado
        /// </summary>       
        public int CuckooScan_Id { get; set; }

        /// <summary>
        /// descripcion de signature
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// contador de mark
        /// </summary>
        public int Markcount { get; set; }

        /// <summary>
        /// listado de marks
        /// </summary>
        public virtual List<Mark> Marks { get; set; }

        /// <summary>
        /// listado de referencias
        /// </summary>
        public virtual List<SignatureReferences> References { get; set; }

        /// <summary>
        /// nivel de severidad
        /// </summary>
        public int Severity { get; set; }
    }
}
