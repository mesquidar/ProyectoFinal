using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class CuckooTarget
    {
        /// <summary>
        /// Id de cuckootarget
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// Id del analsis de cuckoo asociado
        /// </summary>
        public int Cuckoo_Id { get; set; }

        /// <summary>
        /// analisis de cuckoo asociado
        /// </summary>
        public virtual CuckooInfo CuckooInfo { get; set; }

        /// <summary>
        /// calculo crc32
        /// </summary>
        public string crc32 { get; set; }

        /// <summary>
        /// ruta del archivo
        /// </summary>
        public string FilePath { get; set; }

        /// <summary>
        /// calculo md5 
        /// </summary>
        public string md5 { get; set; }

        /// <summary>
        /// nombre del archivo
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// lista de pids
        /// </summary>
        public List<TargetPids> Pids { get; set; }

        /// <summary>
        /// ruta del archivo dentro de windows
        /// </summary>
        public string Path { get; set; }

        /// <summary>
        /// tamaño del archivo
        /// </summary>
        public int Size { get; set; }

        /// <summary>
        /// ssdeep del archivo
        /// </summary>
        public string Ssdeep { get; set; }

        /// <summary>
        /// tipo de archivo
        /// </summary>
        public string Type { get; set; }

        /// <summary>
        /// lista de urls asociada al archivo
        /// </summary>
        public List<TargetUrls> Urls { get; set; }

        /// <summary>
        /// Yaraname encontrado en el archivo
        /// </summary>
        public string YaraName { get; set; }

        /// <summary>
        /// descripcion de yara enconbtrada
        /// </summary>
        public string YaraDescription { get; set; }


    }
}
