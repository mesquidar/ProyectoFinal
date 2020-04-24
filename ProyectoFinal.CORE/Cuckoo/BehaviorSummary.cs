using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class BehaviorSummary
    {
        public int Id { get; set; }

        public int Behavior_Id { get; set; }

        public virtual CuckooBehavior CuckooBehavior {get; set;}

        public string Name { get; set; }

        public string Strings { get; set; }
    }
}
