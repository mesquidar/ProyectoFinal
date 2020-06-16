using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE
{
    public class ScreenShot
    {
        /// <summary>
        /// Id del screenshot
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// malware asociado al screenshot
        /// </summary>
        public virtual Malware Malware { get; set; }

        /// <summary>
        /// id del malware asociado al screenshot
        /// </summary>
        [ForeignKey("Malware")]
        public int Malware_Id { get; set; }


        /// <summary>
        /// ruta del screenshot
        /// </summary>
        public string PathFile { get; set; }
    }
}
