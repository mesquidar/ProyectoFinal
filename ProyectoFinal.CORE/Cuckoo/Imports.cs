using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class Imports
    {
        /// <summary>
        /// id de imports
        /// </summary>
        public int id { get; set; }

        /// <summary>
        /// id asociado a peimport
        /// </summary>
        public int PeImport_Id { get; set; }

        /// <summary>
        /// peimport asociado
        /// </summary>
        public virtual PeImport PeImport { get; set; }

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
