using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class PeResource
    {
        /// <summary>
        /// id de perresource
        /// </summary>
        public int id { get; set; }

        /// <summary>
        /// id de cuckoo static asociado
        /// </summary>
        public int Static_Id { get; set; }

        /// <summary>
        /// cuckoo static asociado
        /// </summary>
        public virtual CuckooStatic CuckooStatic { get; set; }

        /// <summary>
        /// tipo de archivo
        /// </summary>
        public string Filetype { get; set; }

        /// <summary>
        /// language
        /// </summary>
        public string Language { get; set; }

        /// <summary>
        /// nombre
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// ruta offset
        /// </summary>
        public string Offset { get; set; }

        /// <summary>
        /// tamaño archivo
        /// </summary>
        public string Size { get; set; }
    }
}
