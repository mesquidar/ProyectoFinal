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
using ProyectoFinal.IFR.Log;
using ProyectoFinal.Web.Models;
using Microsoft.AspNetCore.SignalR;
using System.Threading;

namespace ProyectoFinal.Web.Controllers
{
    [DisableRequestSizeLimit]
    public class ScanController : Controller
    {
        private readonly IHostingEnvironment _appEnvironment;
        IMalwareManager malwareManager = null;
        ILogEvent _log = null;
        public static string status;
        

        /// <summary>
        /// Contructor del controlador de productos
        /// </summary>
        /// <param name="malwareManager">manager de malware</param>
        /// <param name="log">log</param>
        public ScanController(IMalwareManager malwareManager, ILogEvent log, IHostingEnvironment hostingEnvironment)
        {
            this.malwareManager = malwareManager;
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
                        if (result.Any() == false)
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
                                FilePath = uploads + file.FileName,
                                MalwareStatus = CORE.Status.En_Cola,
                            };

                            //añadiumo y guardamos
                            malwareManager.Add(malware);
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
        /// Metodo de añade producto al carrito
        /// </summary>
        /// <param name="md5">id del producto</param>
        /// <returns></returns>
        public void StartAnalysis(string md5)
        {
            try
            {
                var result = malwareManager.GetByMd5(md5);
                status = "Verificando archivo en VirusTotal";
                return;
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.WriteError(ex.Message, ex);
                Redirect("Index");
            }
            
        }

        [HttpGet]
        public JsonResult GetStatus()
        {
            return Json(status);
        }

    }
}