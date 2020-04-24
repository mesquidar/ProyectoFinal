using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class StaticKeys
    {
        public int Id { get; set; }

        public int CuckooStatic_Id { get; set; }

        public virtual CuckooStatic CuckooStatic { get; set; }

        public string Keys { get; set; }
    }
}
