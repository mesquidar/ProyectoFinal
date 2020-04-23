using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class PeSection
    {
        /// <summary>
        /// id de pesection
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// id del cuckoo static asociado
        /// </summary>
        public int Static_Id { get; set; }

        /// <summary>
        /// cuckoo static asociado
        /// </summary>
        public virtual CuckooStatic CuckooStatic { get; set; }

        /// <summary>
        /// entropia
        /// </summary>
        public double Entropy { get; set; }

        /// <summary>
        /// nombre
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// tamaño de informacion
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
