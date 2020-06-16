using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class MarkCall
    {
        /// <summary>
        /// Id de mark call
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Mark asociado
        /// </summary>
        public virtual Mark Mark { get; set; }

        /// <summary>
        /// id asociado de mark
        /// </summary>
        [ForeignKey("Mark")]
        public int Mark_Id { get; set; }

        /// <summary>
        /// nombre de api
        /// </summary>
        public string Api { get; set; }

        /// <summary>
        /// argumentos de mark
        /// </summary>
        public virtual List<MarkArguments> Arguments { get; set; }

        /// <summary>
        /// categoria de markcall
        /// </summary>
        public string Category { get; set; }

        /// <summary>
        /// status de markcall
        /// </summary>
        public long Status { get; set; }

    }
}
