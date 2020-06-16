using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class CuckooBehavior
    {
        /// <summary>
        /// id de cuckoo behavior
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// analisis de cuckoo asociado
        /// </summary>
        public virtual CuckooInfo CuckooInfo { get; set; }

        /// <summary>
        /// id del analisis de cuckoo asociado
        /// </summary>
        [ForeignKey("CuckoInfo")]
        public int CuckooScan_Id { get; set; }

        /// <summary>
        /// lista de arbol de procesos
        /// </summary>
        public virtual List<ProcessTree> Processtree { get; set; }

        /// <summary>
        /// listado de otra informacion relacionada
        /// </summary>
        public virtual List<BehaviorSummary> Summary { get; set; }
    }
}
