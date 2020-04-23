using System;
using System.Collections.Generic;
using System.Text;

namespace ProyectoFinal.CORE.Cuckoo
{
    public class MarkArguments
    {
        /// <summary>
        /// id de mark arguments
        /// </summary>
        public int Id { get; set; }

        /// <summary>
        /// id de markcall asociado
        /// </summary>
        public int MarkCall_Id { get; set; }

        /// <summary>
        /// markcall asociado
        /// </summary>
        public virtual MarkCall MarkCall { get; set; }

        /// <summary>
        /// direccion base
        /// </summary>
        public string BaseAddress { get; set; }

        /// <summary>
        /// longitud
        /// </summary>
        public long? Length { get; set; }

        /// <summary>
        /// manejador de proceso
        /// </summary>
        public string ProcessHandle { get; set; }

        /// <summary>
        /// identificador de proceso
        /// </summary>
        public int? ProcessIdentifier { get; set; }

        /// <summary>
        /// proteccion 
        /// </summary>
        public int? Protection { get; set; }

        /// <summary>
        /// 
        /// </summary>
        public long? AllocationType { get; set; }

        /// <summary>
        /// tamaño de region
        /// </summary>
        public long? RegionSize { get; set; }

        /// <summary>
        /// bytes libre
        /// </summary>
        public long? FreeBytes { get; set; }

        /// <summary>
        /// ruta raiz
        /// </summary>
        public string RootPath { get; set; }

        /// <summary>
        /// numero total de bytes
        /// </summary>
        public double? TotalNumberOfBytes { get; set; }

        /// <summary>
        /// numero total de bytes libres
        /// </summary>
        public long? TotalNumberOfFreeBytes { get; set; }

        /// <summary>
        /// acceso
        /// </summary>
        public string Access { get; set; }

        /// <summary>
        /// manejador base
        /// </summary>
        public string BaseHandle { get; set; }

        /// <summary>
        /// calve manejador
        /// </summary>
        public string KeyHandle { get; set; }

        /// <summary>
        /// opciones
        /// </summary>
        public long? Options { get; set; }

        /// <summary>
        /// clave de registro
        /// </summary>
        public string Regkey { get; set; }
        public string RegkeyR { get; set; }
    }
}
