using System;
using System.Collections.Generic;
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
        /// id del analisis de cuckoo ascoiado
        /// </summary>
        public int Cuckoo_Id { get; set; }

        /// <summary>
        /// analisis cuckoo asociado
        /// </summary>
        public virtual CuckooInfo CuckooInfo { get; set; }

        /// <summary>
        /// numero de librerias importadas
        /// </summary>
        public int ImportedDllCount { get; set; }

        /// <summary>
        /// listado de claves
        /// </summary>
        public List<string> Keys { get; set; }

        /// <summary>
        /// listado de peexport
        /// </summary>
        public List<PeExport> PeExport { get; set; }

        /// <summary>
        /// peimphash
        /// </summary>
        public string PeImphash { get; set; }

        /// <summary>
        /// listado de peimports
        /// </summary>
        public List<PeImport> PeImports { get; set; }

        /// <summary>
        /// listado de peresources
        /// </summary>
        public List<PeResource> PeResources { get; set; }

        /// <summary>
        /// listado de pesections
        /// </summary>
        public List<PeSection> PeSections { get; set; }

        /// <summary>
        /// timestamp 
        /// </summary>
        public DateTime PeTimestamp { get; set; }

        /// <summary>
        /// listado de firmas
        /// </summary>
        public List<StaticSignature> Signatures { get; set; }
    }
}
