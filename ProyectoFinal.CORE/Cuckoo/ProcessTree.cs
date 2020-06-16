using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class ProcessTree
    {
        /// <summary>
        /// id de process tree
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// cuckoo behavior id asociado
        /// </summary>
        public virtual CuckooBehavior CuckooBehavior { get; set; }

        /// <summary>
        /// id de cuckoo behavior id asociado
        /// </summary>
        [ForeignKey("CuckooBehavior")]
        public int Behavior_Id { get; set; }

        /// <summary>
        /// commando ejecutado
        /// </summary>
        public string CommandLine { get; set; }

        /// <summary>
        /// primer vez visto
        /// </summary>
        public double FirstSeen { get; set; }

        /// <summary>
        /// Pid del archivo
        /// </summary>
        public long Pid { get; set; }

        /// <summary>
        /// Pid padre del archivo
        /// </summary>
        public long Ppid { get; set; }

        /// <summary>
        /// Nombre del proceso
        /// </summary>
        public string ProcessName { get; set; }

        /// <summary>
        /// Ha sido trackeado si o no
        /// </summary>
        public bool Track { get; set; }
    }
}
