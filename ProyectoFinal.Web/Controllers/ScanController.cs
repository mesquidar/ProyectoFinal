using System;
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
using VirusTotalNet;
using VirusTotalNet.Results;
using VirusTotalNet.ResponseCodes;
using ProyectoFinal.CORE.Contracts.VirusTotal;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Diagnostics;
using System.Net;
using Newtonsoft.Json.Linq;

namespace ProyectoFinal.Web.Controllers
{
    [DisableRequestSizeLimit]
    public class ScanController : Controller
    {
        //definimos managers
        private readonly IHostingEnvironment _appEnvironment;
        IMalwareManager malwareManager = null;
        IVirusTotalManager vtManager = null;
        IVirusTotalScanManager vtScanManager = null;
        ILogEvent _log = null;

        //definimos variables que se utilizaran para mostrar el progreso en el front
        public static string status;
        public static int progress;

        //definimos variables que se utilizaran con cuckoo
        private const string CuckooHost = "http://192.168.1.31:8090";
        private const string CuckooApiKey = "VaultApi";


        /// <summary>
        /// Contructor del controlador de productos
        /// </summary>
        /// <param name="malwareManager">manager de malware</param>
        /// <param name="log">log</param>
        public ScanController(IMalwareManager malwareManager, IVirusTotalManager vtManager,IVirusTotalScanManager vtScanManager,
            ILogEvent log, IHostingEnvironment hostingEnvironment)
        {
            this.malwareManager = malwareManager;
            this.vtManager = vtManager;
            this.vtScanManager = vtScanManager;
            _log = log;
            _appEnvironment = hostingEnvironment;
        }

        /// <summary>
        /// Metodo que devuele la vista index
        /// </summary>
        /// <returns>vista index</returns>
        public ActionResult Index()
        {
            return View();
        }

        /// <summary>
        /// Metodo que se encarga de procesar el formulario de index 
        /// </summary>
        /// <param name="model">modelo de datos</param>
        /// <param name="upload">archivo subido</param>
        /// <returns></returns>
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

        /// <summary>
        /// Metodo que devuelve la vista analyze
        /// </summary>
        /// <param name="malware">malware</param>
        /// <returns>vista analyze</returns>
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

        /// <summary>
        /// Metodo que devuelve la vista exist
        /// </summary>
        /// <returns>vista exist</returns>
        public ActionResult Exist()
        {
            return View();
        }

        

        /// <summary>
        /// Metodo que se ejecuta al cargar la pagina de analyze y empieza el analisis del archivo
        /// </summary>
        /// <param name="md5">md5 del producto</param>
        /// <returns></returns>
        public async Task<ActionResult> StartAnalysisFileAsync(int id)
        {
            try
            {
                var malware = malwareManager.GetById(id);

                //await StartVirusTotalFileAsync(malware);

                await StartCuckooAnalysis(malware);
               

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
        /// <param name="malware">malware</param>
        /// <returns></returns>
        public async Task StartVirusTotalFileAsync(Malware malware)
        {
            try
            {
                // creamos una nueva instanca de virustotal pasandole la API obtenida
                VirusTotal virusTotal = new VirusTotal("8dfa583388406b434fd2c2fb3882f20283bbc8f2c3fb9ef73be09ca4b3f8d2ab");

                

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
                    VirusTotalAnalysisFile(fileReport, malware);

                }
                else
                {
                    ScanResult fileResult = await virusTotal.ScanFileAsync(file, malware.FileName);
                    FileReport fileReportScan = await virusTotal.GetFileReportAsync(fileResult.Resource);
                    VirusTotalAnalysisFile(fileReportScan, malware);

                }
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.WriteError(ex.Message, ex);
                Redirect("Index");
            }
        }

        /// <summary>
        /// Metodo que obtiene y guarda los resultados del analisis realizado en virusTotal
        /// </summary>
        /// <param name="virusTotal">virustotal</param>
        /// <param name="malware">malware</param>
        /// <returns></returns>
        public void VirusTotalAnalysisFile(FileReport fileReport, Malware malware)
        {
            try
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

                vtManager.Add(info);
                vtManager.Context.SaveChanges();

                //convertimos el diccionario en lista y de cada escaneo lo guardamos en la tabls

                foreach (var key in fileReport.Scans.ToList())
                {
                    CORE.VirusTotal.VirusTotalScans scans = new CORE.VirusTotal.VirusTotalScans
                    {
                        VirusTotal_Id = info.Id,
                        Name = key.Key,
                        Version = key.Value.Version,
                        Detected = key.Value.Detected,
                        Result = key.Value.Result

                    };

                    vtScanManager.Add(scans);
                }
                progress = 20;
                vtScanManager.Context.SaveChanges();
                progress = 25;
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.WriteError(ex.Message, ex);
                Redirect("Index");
            }

        }

        /// <summary>
        /// Metodo que inicializa el analsis con cuckoo
        /// </summary>
        /// <param name="malware">malware</param>
        /// <returns></returns>
        public async Task StartCuckooAnalysis(Malware malware)
        {
            try
            {

                //creamos nuevo cliente http
                HttpClient client = new HttpClient();
                client.BaseAddress = new Uri(CuckooHost);
                client.DefaultRequestHeaders.Clear();

                //cremos un unevo request en modo POST
                var request = new HttpRequestMessage(new HttpMethod("POST"), CuckooHost + "/tasks/create/file");

                //añadimos cabecera de autenticacion necesaria para el REST API de Cuckoo
                request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + CuckooApiKey);

                //activity.current se deja en null sino net core añade request id que da problemas con la API de cuckoo
                Activity.Current = null;

                //cargamos el archivo en formato MultipartFormDataContent 
                var multipartContent = new MultipartFormDataContent();
                multipartContent.Add(new ByteArrayContent(System.IO.File.ReadAllBytes(malware.FilePath)), "file", Path.GetFileName(malware.FilePath));
                request.Content = multipartContent;

                //mandamos la solictud y recibimos la resuesta
                var response = await client.SendAsync(request);

                //si la respuesta e spositiva Codigo 200
                if (response.IsSuccessStatusCode)
                {
                    //recogemos la respuesta
                    HttpContent content = response.Content;
                    await content.ReadAsStringAsync();
                    //leemos el resultado y lo pasamos a string
                    var result = content.ReadAsStringAsync();
                    string res = result.Result;
                    // del resultado obtenido en string lo pasamos a json y obtenimos el id de la tarea
                    dynamic data = JObject.Parse(res);
                    int task = data.task_id;
                    //lanzamos el siguiente metodo que esperara a que termine el analisis dentro de cuckoo
                    await WaitStatusCuckoo(task);
                    await GetCuckooReport(task,malware);

                }
                else
                {
                    Console.WriteLine("{0} ({1}) {2}", (int)response.StatusCode, response.ReasonPhrase, response.RequestMessage);
                }



            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.WriteError(ex.Message, ex);
                Redirect("Index");//guardamos el log si se produce una excepcion
            }

        }

        /// <summary>
        /// Metodo que se encarga de revisar si el analisis en cuckoo ha terminado correctamente
        /// </summary>
        /// <param name="id">id de la tarea a esperar</param>
        /// <returns></returns>
        public async Task WaitStatusCuckoo(int id)
        {
            string status = "pending";

            while (status != "reported")
            {
                using (var httpClient = new HttpClient())
                {
                    using (var request = new HttpRequestMessage(new HttpMethod("GET"), CuckooHost+"/tasks/view/"+id))
                    {
                        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + CuckooApiKey);

                        var response = await httpClient.SendAsync(request);

                        //si la respuesta e spositiva Codigo 200
                        if (response.IsSuccessStatusCode)
                        {
                            //recogemos la respuesta
                            HttpContent content = response.Content;
                            await content.ReadAsStringAsync();
                            var result = content.ReadAsStringAsync();
                            string res = result.Result;
                            // del resultado obtenido en string lo pasamos a json y obtenimos el id de la tarea
                            dynamic data = JObject.Parse(res);
                            Console.WriteLine(data);
                            Console.WriteLine(data.task.status);
                            status = data.task.status;
                            await Task.Delay(3000);

                        }
                        else
                        {
                            Console.WriteLine("{0} ({1}) {2}", (int)response.StatusCode, response.ReasonPhrase, response.RequestMessage);
                        }

                    }
                }
            }

        }

        public async Task GetCuckooReport(int id, Malware malware)
        {
    
                using (var httpClient = new HttpClient())
                {
                    using (var request = new HttpRequestMessage(new HttpMethod("GET"), CuckooHost + "/tasks/summary/" + id))
                    {
                        request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + CuckooApiKey);

                        var response = await httpClient.SendAsync(request);

                        //si la respuesta e spositiva Codigo 200
                        if (response.IsSuccessStatusCode)
                        {
                            //recogemos la respuesta
                            HttpContent content = response.Content;
                            await content.ReadAsStringAsync();
                            var result = content.ReadAsStringAsync();
                            string res = result.Result;
                            // del resultado obtenido en string lo pasamos a json y obtenimos el id de la tarea
                            dynamic data = JObject.Parse(res);




                            await Task.Delay(3000);

                        }
                        else
                        {
                            Console.WriteLine("{0} ({1}) {2}", (int)response.StatusCode, response.ReasonPhrase, response.RequestMessage);
                        }

                    }
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