using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class YaraDropped
    {
        /// <summary>
        /// Id de yaradropped
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// cuckoo dropped asociado
        /// </summary>
        public virtual CuckooDropped CuckooDropped { get; set; }

        /// <summary>
        /// id de cuckoo dropped asociado
        /// </summary>
        [ForeignKey("CuckooDropped")]
        public int Dropped_Id { get; set; }

        

        /// <summary>
        /// calculo crc32
        /// </summary>
        public string crc32 { get; set; }

        /// <summary>
        /// nombre de yata dropped
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// descripcion de yaradropped
        /// </summary>
        public string Description { get; set; }
    }
}
