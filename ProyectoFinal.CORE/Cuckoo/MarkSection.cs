using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class MarkSection
    {
        /// <summary>
        /// id de mark section
        /// </summary>
        public int id { get; set; }

        /// <summary>
        /// mark asociado
        /// </summary>
        public virtual Mark Mark { get; set; }

        /// <summary>
        /// id de mark asociado
        /// </summary>
        [ForeignKey("Mark")]
        public int Mark_Id { get; set; }

        /// <summary>
        /// entropia
        /// </summary>
        public long Entropy { get; set; }

        /// <summary>
        /// nombre de section
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// tamaño de la informacion
        /// </summary>
        public string SizeOfData { get; set; }

        /// <summary>
        /// direccion virtual
        /// </summary>
        public string VirtualAddress { get; set; }

        /// <summary>
        /// tamaño virtual
        /// </summary>
        public string VirtualSize { get; set; }
    }
}
