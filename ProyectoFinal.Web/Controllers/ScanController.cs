using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.VirusTotal;
using ProyectoFinal.IFR.Log;
using ProyectoFinal.Web.Models;
using VirusTotalNet;
using Microsoft.AspNetCore.SignalR;
using System.Threading;
using VirusTotalNet.Results;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Objects;
using ProyectoFinal.CORE.Contracts.VirusTotal;

namespace ProyectoFinal.Web.Controllers
{
    [DisableRequestSizeLimit]
    public class ScanController : Controller
    {
        private readonly IHostingEnvironment _appEnvironment;
        IMalwareManager malwareManager = null;
        IVirusTotalManager vtManager = null;
        IVirusTotalScanManager vtScanManager = null;
        IVirusTotalCommentManager vtCommentManager = null;
        ILogEvent _log = null;
        public static string status;
        public static int progress;


        /// <summary>
        /// Contructor del controlador de productos
        /// </summary>
        /// <param name="malwareManager">manager de malware</param>
        /// <param name="log">log</param>
        public ScanController(IMalwareManager malwareManager, IVirusTotalManager vtManager,IVirusTotalScanManager vtScanManager,
            IVirusTotalCommentManager vtCommentManager, ILogEvent log, IHostingEnvironment hostingEnvironment)
        {
            this.malwareManager = malwareManager;
            this.vtManager = vtManager;
            this.vtScanManager = vtScanManager;
            this.vtCommentManager = vtCommentManager;
            _log = log;
            _appEnvironment = hostingEnvironment;
        }

        // GET: Scan
        public ActionResult Index()
        {
            return View();
        }

        [Authorize(Roles = "Admin,Business,Professional,Registered")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Index(MalwareViewModel model, IFormFile upload)
        {
            try
            {

                //gverfificamos el archivo
                var file = Request.Form.Files["upload"];
                //si el archivo esta vacio devolvemos a la misma pagina con mensaje
                if (file == null)
                {
                    TempData["vacio"] = "No hay ningún archivo adjuntado para analizar";

                    return View(model);

                }
                //si no pasamos a siguiente 
                else
                {
                    // si el tamaño del archivo excede los 120mb se deveulve el formulrio de nuevo indicando error de tamaño
                    if (file.Length > 125829120)
                    {
                        TempData["grande"] = "El archivo subido es demasiado grande";

                        return View(model);
                    }
                    else
                    {                        

                        //guardamos la ruta
                        var uploads = Path.Combine(_appEnvironment.WebRootPath, "Uploads/Malware");

                        //miramos que el archivo no este vacio
                        if (file.Length > 0)
                        {
                            using (var fileStream = new FileStream(Path.Combine(uploads, file.FileName), FileMode.Create))
                            {                              
                                file.CopyTo(fileStream);

                            }

                        }

                        //revisamos si un archivo ha sido ya subido mediante su hash md5
                        string resultMd5 = malwareManager.checkMD5(Path.Combine(uploads, file.FileName));
                        var result = malwareManager.GetByMd5(resultMd5);
                        //si no esta subida se realizara el analisis
                        if (result == null)
                        {

                            //creamos el nuevo malware
                            CORE.Malware malware = new CORE.Malware
                            {
                                Name = model.Name,
                                FileName = file.FileName,
                                User_Id = User.FindFirstValue(ClaimTypes.NameIdentifier),
                                Date = DateTime.Now,
                                MD5 = malwareManager.checkMD5("wwwroot/Uploads/Malware/" + file.FileName),
                                SHA256 = malwareManager.checkSHA("wwwroot/Uploads/Malware/" + file.FileName),
                                FilePath = Path.Combine(uploads, file.FileName),
                                MalwareStatus = CORE.Status.En_Cola,
                            };

                            //añadiumo y guardamos
                            malwareManager.AddAsync(malware);
                            malwareManager.Context.SaveChanges();
                            TempData["creado"] = "Su muestra se ha subido correctamente";

                            return View("Analyze", malwareManager.GetByMd5(malware.MD5));
                        }
                        //si esta subido se dirigira al usuario al analisis de esta forma evitamos duplicar trabajos de analisis
                        else{

                            //TODO
                            TempData["exist"] = "El archivo ya existe sera redirigido en unos segundos al analisis correspondiente";
                            return RedirectToAction("Exist");
                        }

                    }


                }

            }
            catch (Exception ex)
            {
                //guardamso log si se produce una excepcion
                _log.WriteError(ex.Message, ex);
                return View(model);
            }
        }

        // GET: Scan/A/
        public ActionResult Analyze(Malware malware)
        {
            if (malware != null)
            {
                
                return View(malware);

                
            }
            else
            {
                TempData["analyze"] = "No se puede visualizar un analisis sin el malware correspondiente";
                return View("Index");
                
            }  
            
        }


        public ActionResult Exist()
        {
            return View();
        }

        

        /// <summary>
        /// Metodo que se ejecuta al cargar la pagina de analyze y empieza el analisis del archivo
        /// </summary>
        /// <param name="md5">md5 del producto</param>
        /// <returns></returns>
        public ActionResult StartAnalysisFile(int id)
        {
            try
            {
           
                StartVirusTotalFileAsync(id);
                progress = 2;

                return null;
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.WriteError(ex.Message, ex);
                return Redirect("Index");
            }
            
        }
        /// <summary>
        /// Metodo que ejecuta el analisis de los archivos en virustotal de forma asincrona
        /// </summary>
        /// <param name="malware"></param>
        /// <returns></returns>
        public async void StartVirusTotalFileAsync(int id)
        {
            VirusTotal virusTotal = new VirusTotal("8dfa583388406b434fd2c2fb3882f20283bbc8f2c3fb9ef73be09ca4b3f8d2ab");

            var malware = malwareManager.GetById(id);

            progress = 5;
            //Usamos HTTPS en vez de HTTP normal
            virusTotal.UseTLS = true;

            status = "Leyendo archivo...";
            //Pasamos el archivo a bytes dentro de una array de bytes
            byte[] file = System.IO.File.ReadAllBytes(malware.FilePath);

           

            status = "Verificando archivo en VirusTotal...";
            progress = 10;

            //Verificamos si el archivo ya se ha analizado antes
            FileReport fileReport = await virusTotal.GetFileReportAsync(file);
            

            bool hasFileBeenScannedBefore = fileReport.ResponseCode == FileReportResponseCode.Present;

            //Si los resultados han sido escaneado antes se guardan en la base de datos
            if (hasFileBeenScannedBefore)
            {
                //ontenemos la informacion de los resultados y las guardamos en la tabla de VTInfo
                status = "Archivo encontrado en VirusTotal. Obteniendo Información...";
                progress = 12;


                CORE.VirusTotal.VirusTotalInfo info = new CORE.VirusTotal.VirusTotalInfo
                {
                    Malware_Id = malware.Id,
                    Total = fileReport.Total,
                    Positives = fileReport.Positives,
                };

                status = "Guardando Resultados...";
                progress = 15;

                await vtManager.AddAsync(info);
                await vtManager.Context.SaveChangesAsync();

                //convertimos el diccionario en lista y de cada escaneo lo guardamos en la tabls

                foreach (var key in fileReport.Scans.ToList())
                {
                    CORE.VirusTotal.VirusTotalScans scans = new CORE.VirusTotal.VirusTotalScans
                    {
                        VirusTotal_Id = info.Id,
                        Name = key.Key,
                        Version = key.Value.Version,
                        Detected = key.Value.Detected,
                        Result = key.Value.Version

                    };

                    vtScanManager.Add(scans);
                }
                progress = 20;
                vtScanManager.Context.SaveChanges();

                //obtenemos los comentarios desde VirusTotal del analisis 
                status = "Obteniendo Comentarios...";
                progress = 25;
                CommentResult comments = await virusTotal.GetCommentAsync(file);

                // de cada comentario los guardamos en la tabla
                foreach (var com in comments.Comments)
                {
                    CORE.VirusTotal.VirusTotalComments mCom = new CORE.VirusTotal.VirusTotalComments
                    {
                        VirusTotal_Id = info.Id,
                        Date = com.Date,
                        Comment = com.Comment
                        
                    };

                    vtCommentManager.Add(mCom);
                }
                status = "Guardando Comentarios...";
                progress = 30;

                vtCommentManager.Context.SaveChanges();

            }
            else
            {
                ScanResult fileResult = await virusTotal.ScanFileAsync(file, malware.FileName);
                
            }
        }

        /// <summary>
        /// Metodo que obtiene el estado del analisis del archivo o url
        /// </summary>
        /// <returns>devuelve el estado del analisis</returns>
        [HttpGet]
        public JsonResult GetStatus()
        {
            return Json(status);
        }

        /// <summary>
        /// Metodo que obtiene el progrso del analisis del archivo o url
        /// </summary>
        /// <returns>devuelve el progreso del analisis</returns>
        [HttpGet]
        public JsonResult GetProgress()
        {
            return Json(progress);
        }

    }
}