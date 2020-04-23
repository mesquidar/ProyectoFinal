using System;
using System.Collections.Generic;
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
        /// id del analisis de cuckoo asociado
        /// </summary>
        public int Cuckoo_Id { get; set; }

        /// <summary>
        /// analisis de cuckoo asociado
        /// </summary>
        public virtual CuckooInfo CuckooInfo { get; set; }

        /// <summary>
        /// lista de arbol de procesos
        /// </summary>
        public List<ProcessTree> Processtree { get; set; }

        /// <summary>
        /// diccionario de otra informacion relacionada
        /// </summary>
        public Dictionary<string, List<string>> Summary { get; set; }
    }
}
