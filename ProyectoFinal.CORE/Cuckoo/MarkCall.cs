using System;
using System.Collections.Generic;
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
        /// id asociado de mark
        /// </summary>
        public int Mark_Id { get; set; }

        /// <summary>
        /// Mark asociado
        /// </summary>
        public virtual Mark Mark { get; set; }

        /// <summary>
        /// nombre de api
        /// </summary>
        public string Api { get; set; }

        /// <summary>
        /// argumentos de mark
        /// </summary>
        public MarkArguments Arguments { get; set; }

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
