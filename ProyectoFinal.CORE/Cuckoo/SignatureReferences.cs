using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class SignatureReferences
    {

        public int Id { get; set; }

        public virtual CuckooSignature CuckooSignature { get; set; }

        [ForeignKey("CuckooSignature")]
        public int CuckooSignature_Id { get; set; }

        

        public string References { get; set; }


    }
}
