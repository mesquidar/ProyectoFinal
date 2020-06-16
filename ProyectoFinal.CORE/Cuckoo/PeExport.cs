using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class PeExport
    {
        /// <summary>
        /// Id de peexport
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// cuckoo static asociado
        /// </summary>
        public virtual CuckooStatic CuckooStatic { get; set; }

        /// <summary>
        /// id de cuckoo static asociado
        /// </summary>
        [ForeignKey("CuckooStatic")]
        public int CuckooStatic_Id { get; set; }

        /// <summary>
        /// nombre del libreria
        /// </summary>
        public string Dll { get; set; }

        /// <summary>
        /// listado de exports
        /// </summary>
        public virtual List<Exports> Exports { get; set; }
    }
}
