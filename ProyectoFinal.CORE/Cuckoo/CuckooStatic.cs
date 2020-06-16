using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class CuckooStatic
    {
        /// <summary>
        /// id de cuckoo static
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// analisis cuckoo asociado
        /// </summary>
        [ForeignKey("CuckooScanId")]
        public virtual CuckooInfo CuckooInfo { get; set; }

        /// <summary>
        /// id del analisis de cuckoo ascoiado
        /// </summary>
        public int CuckooScan_Id { get; set; }

        /// <summary>
        /// numero de librerias importadas
        /// </summary>
        public int ImportedDllCount { get; set; }

        /// <summary>
        /// listado de claves
        /// </summary>
        public virtual List<StaticKeys> Keys { get; set; }

        /// <summary>
        /// listado de peexport
        /// </summary>
        public virtual List<PeExport> PeExport { get; set; }

        /// <summary>
        /// peimphash
        /// </summary>
        public string PeImphash { get; set; }

        /// <summary>
        /// listado de peimports
        /// </summary>
        public virtual List<PeImport> PeImports { get; set; }

        /// <summary>
        /// listado de peresources
        /// </summary>
        public virtual List<PeResource> PeResources { get; set; }

        /// <summary>
        /// listado de pesections
        /// </summary>
        public virtual List<PeSection> PeSections { get; set; }

        /// <summary>
        /// timestamp 
        /// </summary>
        public DateTime PeTimestamp { get; set; }

        /// <summary>
        /// listado de firmas
        /// </summary>
        public virtual List<StaticSignature> Signatures { get; set; }
    }
}
