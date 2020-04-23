using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks.Sources;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class CuckooInfo
    {
        /// <summary>
        /// Id del analsis de cuckoo
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Id del malware asociado
        /// </summary>
        public int Malware_Id { get; set; }

        /// <summary>
        /// Malware asociado
        /// </summary>
        public virtual Malware Malware { get; set; }

        /// <summary>
        /// Categoria de cuckoo
        /// </summary>
        public string Category { get; set; }

        /// <summary>
        /// Paquete de cuckoo
        /// </summary>
        public string Package { get; set; }

        /// <summary>
        /// Puntuacion otorgada por cuckoo
        /// </summary>
        public float Score { get; set; }
    }
}
