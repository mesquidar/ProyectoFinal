﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class CuckooDropped
    {
        /// <summary>
        /// Id de cuckoo dropped
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// analisis cuckoo asociado
        /// </summary>
        [ForeignKey("CuckooScanId")]
        public virtual CuckooInfo CuckoInfo { get; set; }

        /// <summary>
        /// id del analisi de cuckoo asociado
        /// </summary>
        public int CuckooScan_Id { get; set; }

        /// <summary>
        /// calculo crc32
        /// </summary>
        public string crc32 { get; set; }

        /// <summary>
        /// tuta del archivo
        /// </summary>
        public string FilePath { get; set; }

        /// <summary>
        /// calculo md5 del archivo dropped
        /// </summary>
        public string md5 { get; set; }

        /// <summary>
        /// nombre del archivo dropeado
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// ruta del archivo dentro de windows
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        /// lista de pids del archivo
        /// </summary>
        public virtual List<DroppedPids> Pids { get; set; }

        /// <summary>
        /// tamaño del archivo
        /// </summary>
        public int Size { get; set; }

        /// <summary>
        /// lista de urls en caso de que haya
        /// </summary>
        public virtual List<DroppedUrls> Urls { get; set; }

        /// <summary>
        /// lista de yaradropped
        /// </summary>
        public virtual List<YaraDropped> YaraDroppeds { get; set; }
    }
}
