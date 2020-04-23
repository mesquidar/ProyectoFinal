using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class Exports
    {
        /// <summary>
        /// id de exports
        /// </summary>
        public int id { get; set; }

        /// <summary>
        /// id asociado a pexport
        /// </summary>
        public int PeExport_Id { get; set; }

        /// <summary>
        /// pexport asociado
        /// </summary>
        public virtual PeExport PeExport {get; set;}

        /// <summary>
        /// direccion 
        /// </summary>
        public string Address { get; set; }

        /// <summary>
        /// nombre
        /// </summary>
        public string Name { get; set; }
    }
}
