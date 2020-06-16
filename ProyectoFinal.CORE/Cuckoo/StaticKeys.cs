using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class StaticKeys
    {
        public int Id { get; set; }

        public virtual CuckooStatic CuckooStatic { get; set; }

        [ForeignKey("CuckooStatic")]
        public int CuckooStatic_Id { get; set; }

       

        public string Keys { get; set; }
    }
}
