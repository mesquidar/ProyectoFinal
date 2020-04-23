using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class StaticSignature
    {
        /// <summary>
        /// id de static signature
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// id de cuckoo static asociado
        /// </summary>
        public int Static_Id { get; set; }

        /// <summary>
        /// cuckoo static asociado
        /// </summary>
        public virtual CuckooStatic CuckooStatic { get; set; }

        /// <summary>
        /// nombre 
        /// </summary>
        public string CommonName { get; set; }

        /// <summary>
        /// pais 
        /// </summary>
        public string Country { get; set; }

        /// <summary>
        /// email
        /// </summary>
        public string Email { get; set; }

        /// <summary>
        /// localidad
        /// </summary>
        public string Locality { get; set; }

        /// <summary>
        /// organizacion
        /// </summary>
        public string Organization { get; set; }

        /// <summary>
        /// numero de serie
        /// </summary>
        public string SerialNumber { get; set; }
    }
}
