using System;
using System.Reflection;
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
using ProyectoFinal.CORE.Contracts.Cuckoo;
using System.IO.Compression;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using Microsoft.Extensions.Logging;
using ProyectoFinal.IFR.Email;
using System.Collections.Generic;

namespace ProyectoFinal.Web.Controllers
{
    [Authorize(Roles = "Admin,Business,Professional,Registered")]
    [DisableRequestSizeLimit]
    public class ScanController : Controller
    {
        //definimos managers
        private readonly IHostingEnvironment _appEnvironment;
        IMalwareManager malwareManager = null;
        IVirusTotalManager vtManager = null;
        IVirusTotalScanManager vtScanManager = null;
        ICuckooInfoManager cuckooInfoManager = null;
        ICuckooTargetManager cuckooTargetManager = null;
        ITargetPidsManager targetPidsManager = null;
        ITargetUrlsManager targetUrlsManager = null;
        ICuckooDroppedManager droppedManager = null;
        IDroppedPidsManager droppedPidsManager = null;
        IDroppedUrlsManager droppedUrlsManager=null;
        ICuckooStringsManager cuckooStringsManager = null;
        ICuckooStaticManager cuckooStaticManager = null;
        IPeImportsManager peImportsManager = null;
        IPeExportsManager peExportsManager = null;
        IImportsManager importsManager = null;
        IExportsManager exportsManager = null;
        IPeResourcesManager peResourcesManager = null;
        IPeSectionsManager peSectionsManager = null;
        IStaticKeysManager staticKeysManager = null;
        IStaticSignaturesManager staticSignaturesManager = null;
        ICuckooBehaviorManager cuckooBehaviorManager = null;
        IProcessTreeManager processTreeManager = null;
        IBehaviorSummaryManager BehaviorSummaryManager = null;
        ICuckooSigantureManager cuckooSigantureManager = null;
        IScreenShotManager screenShotManager = null;
        IThreatCrowdInfoManager threatCrowdInfoManager = null;
        ITCDomainsManager tCDomainsManager = null;
        ITCEmailsManager tCEmailsManager = null;
        ITCHashesManager tCHashesManager = null;
        ITCIpsManager tCIpsManager = null;
        ITCReferencesManager tCReferencesManager = null;
        ITCResolutionManager tCResolutionManager = null;
        ITCScansManager tCScansManager = null;
        ITCSubdomainsManager tCSubdomainsManager = null;
        ILogger<ScanController> _log = null;
        IEmailService email = null;

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
            ICuckooInfoManager cuckooInfoManager, ILogger<ScanController> log, IHostingEnvironment hostingEnvironment,
            ICuckooTargetManager cuckooTargetManager, ITargetUrlsManager targetUrlsManager, ITargetPidsManager targetPidsManager,
            ICuckooDroppedManager droppedManager,IDroppedUrlsManager droppedUrlsManager, IDroppedPidsManager droppedPidsManager,
            ICuckooStaticManager cuckooStaticManager, IPeExportsManager peExportsManager, IPeImportsManager peImportsManager,
            IImportsManager importsManager, IExportsManager exportsManager, IPeResourcesManager peResourcesManager, IPeSectionsManager peSectionsManager,
            IStaticKeysManager staticKeysManager, IStaticSignaturesManager staticSignaturesManager,ICuckooBehaviorManager cuckooBehaviorManager,
            IProcessTreeManager processTreeManager, IBehaviorSummaryManager BehaviorSummaryManager, ICuckooSigantureManager cuckooSigantureManager,
            IScreenShotManager screenShotManager, IThreatCrowdInfoManager threatCrowdInfoManager, ITCDomainsManager tCDomainsManager, ITCEmailsManager tCEmailsManager,
            ITCHashesManager tCHashesManager, ITCIpsManager tCIpsManager, ITCReferencesManager tCReferencesManager, ITCResolutionManager tCResolutionManager,
            ITCScansManager tCScansManager, ITCSubdomainsManager tCSubdomainsManager, ICuckooStringsManager cuckooStringsManager,
            IEmailService email)
        {
            this.malwareManager = malwareManager;
            this.vtManager = vtManager;
            this.vtScanManager = vtScanManager;
            this.cuckooInfoManager = cuckooInfoManager;
            this.cuckooTargetManager = cuckooTargetManager;
            this.targetPidsManager = targetPidsManager;
            this.targetUrlsManager = targetUrlsManager;
            this.droppedManager = droppedManager;
            this.droppedPidsManager = droppedPidsManager;
            this.droppedUrlsManager = droppedUrlsManager;
            this.cuckooStaticManager = cuckooStaticManager;
            this.peResourcesManager = peResourcesManager;
            this.peSectionsManager = peSectionsManager;
            this.peImportsManager = peImportsManager;
            this.peExportsManager = peExportsManager;
            this.importsManager = importsManager;
            this.exportsManager = exportsManager;
            this.staticKeysManager = staticKeysManager;
            this.staticSignaturesManager = staticSignaturesManager;
            this.cuckooBehaviorManager = cuckooBehaviorManager;
            this.processTreeManager = processTreeManager;
            this.BehaviorSummaryManager = BehaviorSummaryManager;
            this.cuckooSigantureManager = cuckooSigantureManager;
            this.screenShotManager = screenShotManager;
            this.threatCrowdInfoManager = threatCrowdInfoManager;
            this.tCDomainsManager = tCDomainsManager;
            this.tCEmailsManager = tCEmailsManager;
            this.tCHashesManager = tCHashesManager;
            this.tCIpsManager = tCIpsManager;
            this.tCReferencesManager = tCReferencesManager;
            this.tCResolutionManager = tCResolutionManager;
            this.tCScansManager = tCScansManager;
            this.tCSubdomainsManager = tCSubdomainsManager;
            this.cuckooStringsManager = cuckooStringsManager;
            this.email = email;
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
                    // si el tamaño del archivo excede los 30mb se deveulve el formulrio de nuevo indicando error de tamaño
                    if (file.Length > 31457280)
                    {
                        TempData["grande"] = "El archivo subido es demasiado grande, pruebe utilizando una url";

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

                            TempData["exist"] = "El archivo subido ya ha sido analizado este es su analisis correspondiente";
                            return RedirectToAction("Index", "Analysis", new { id = result.MD5 });
                        }

                    }


                }

            }
            catch (Exception ex)
            {
                //guardamso log si se produce una excepcion
                _log.LogError(ex.Message, ex);
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
                //obtenemos el malware a analizar
                var malware = malwareManager.GetById(id);

                //lanzamos el metodo que empezara el analisis de virustotal
                await StartVirusTotalFileAsync(malware);
                //lanzamos el metodo que empezara el analisis de cuckoo
                int cuckooId = await StartCuckooAnalysis(malware);
                //lanzamos metodo que obtendra el informe del analisis realizado si el id de cuckoo es diferente 0
                if (cuckooId != 0)
                {
                    dynamic report = await GetCuckooReport(cuckooId);
                    //lanzamos metodo que guardara el report en base de datos
                    SaveCuckooReport(report, malware);
                }
                //lanzamos metodo que obtiene los screenshots realizados por cuckoo
                await GetScreenShotsAsync(cuckooId,malware.Id);
                //metodo que empieza el analisis de threatcrowd
                await StartThreatCrowdAnalysisAsync(malware.Id, malware.MD5);
                //metoso que actualiza el estado del malware
                UpdateMalware(malware);
                
                return RedirectToAction("Index", "Analysis", new { id = malware.MD5 });
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.LogError(ex.Message, ex);
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
                _log.LogError(ex.Message, ex);
                UpdateMalware(malware);
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
                    MD5 = malware.MD5
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
                _log.LogError(ex.Message, ex);
                UpdateMalware(malware);
                Redirect("Index");
            }

        }

        /// <summary>
        /// Metodo que inicializa el analsis con cuckoo
        /// </summary>
        /// <param name="malware">malware</param>
        /// <returns></returns>
        public async Task<int> StartCuckooAnalysis(Malware malware)
        {
            try
            {
                int task = 0;
                progress = 30;
                status = "Empezando análisis en Cuckoo Sandbox...";
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
                progress = 32;
                status = "Subiendo archivo...";

                //cargamos el archivo en formato MultipartFormDataContent 
                var multipartContent = new MultipartFormDataContent();
                multipartContent.Add(new ByteArrayContent(System.IO.File.ReadAllBytes(malware.FilePath)), "file", Path.GetFileName(malware.FilePath));
                request.Content = multipartContent;

                //mandamos la solictud y recibimos la resuesta
                var response = await client.SendAsync(request);

                //si la respuesta es positiva Codigo 200
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
                    task = data.task_id;
                    //lanzamos el siguiente metodo que esperara a que termine el analisis dentro de cuckoo
                    progress = 35;
                    status = "Esperando a que termine el análisis...";
                    await WaitStatusCuckoo(task);
                    //cambiamos el estado del malware
                    malware.MalwareStatus = Status.Analizando;
                    malwareManager.Context.SaveChanges();
                }
                else
                {
                    Console.WriteLine("{0} ({1}) {2}", (int)response.StatusCode, response.ReasonPhrase, response.RequestMessage);
                    Redirect("Index");
                }

                return task;
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.LogError(ex.Message, ex);
                UpdateMalware(malware);
                 Redirect("Index");//guardamos el log si se produce una excepcion
                return 0;

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

        /// <summary>
        /// Metodo que obtiene el informe del malware analizado en cuckoo
        /// </summary>
        /// <param name="id">id del analisis</param>
        /// <returns>informe</returns>
        public async Task<dynamic> GetCuckooReport(int id)
        {
            progress = 40;
            status = "Obteniendo informe...";
    
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
                            //string res = result.Result;
                            // del resultado obtenido en string lo pasamos a json y obtenimos el id de la tarea
                            JObject data = JObject.Parse(result.Result);
                        

                        return data;

                        }
                        else
                        {
                            Console.WriteLine("{0} ({1}) {2}", (int)response.StatusCode, response.ReasonPhrase, response.RequestMessage);
                        return null;
                        }

                    }
                }
            }

        public void SaveCuckooReport(dynamic data, Malware malware)
         {
            try
            {
                progress = 42;
                status = "Guardando Cuckoo Info...";
                //creamos un nuevo modelo de CuckooInfo donde le pasamos los datos obtenidos del analisis
                CORE.Cuckoo.CuckooInfo info = new CORE.Cuckoo.CuckooInfo
                {
                    CuckooScanId = data.info.id,
                    Malware_Id = malware.Id,
                    Category = data.info.category,
                    Package = data.info.package,
                    Score = data.info.score,
                    MD5 = malware.MD5
                };
                
                cuckooInfoManager.Add(info);
                cuckooInfoManager.Context.SaveChanges();

                progress = 44;
                status = "Guardando Cuckoo Target...";

                //creamos un nuevo modelo de cuckoo target para guardar los datos obtenidos
                CORE.Cuckoo.CuckooTarget target = new CORE.Cuckoo.CuckooTarget
                {
                    CuckooScan_Id = data.info.id,
                    crc32 = data.target.file.crc32,
                    md5 = data.target.file.md5,
                    Name = data.target.file.name,
                    Path = data.target.file.path,
                    Size = data.target.file.size,
                    Ssdeep = data.target.file.ssdeep,
                };

                cuckooTargetManager.Add(target);
                cuckooTargetManager.Context.SaveChanges();

                progress = 46;
                status = "Guardando Target Urls...";
                //por cada targeturl que haya la insertamos en la tabla TargetUrls               
                foreach (var url in data.target.file.urls)
                {
                    CORE.Cuckoo.TargetUrls tUrls = new CORE.Cuckoo.TargetUrls
                    {
                        Target_Id = target.Id,
                        Url = url
                    };

                    targetUrlsManager.Add(tUrls);
                };

                targetUrlsManager.Context.SaveChanges();

                //por cada targeturl que haya la insertamos en la tabla TargetUrls
                if (data.target.file.pids != null)
                {
                    foreach (var pid in data.target.file.pids)
                    {
                        CORE.Cuckoo.TargetPids tPids = new CORE.Cuckoo.TargetPids
                        {
                            Target_Id = target.Id,
                            Pid = pid
                        };

                        targetPidsManager.Add(tPids);
                    };

                    targetUrlsManager.Context.SaveChanges();
                }
               


                //guardamos cuckoo dropped porcada archivo droppeado que haya
                progress = 48;
                status = "Guardando Cuckoo Dropped...";
                foreach (var drop in data.dropped)
                {
                    CORE.Cuckoo.CuckooDropped dropped = new CORE.Cuckoo.CuckooDropped
                    {
                        CuckooScan_Id = data.info.id,
                        crc32 = drop.crc32,
                        FilePath = drop.filepath,
                        md5 = drop.md5,
                        Name = drop.name,
                        Path = drop.path,
                        Size = drop.size,
                    };

                    droppedManager.Add(dropped);
                    droppedManager.Context.SaveChanges();
                    //guardamos los pids del dropped
                    if (drop.pids != null)
                    {
                        foreach (var pid in drop.pids)
                        {
                            CORE.Cuckoo.DroppedPids droppedPids = new CORE.Cuckoo.DroppedPids
                            {
                                Dropped_Id = dropped.Id,
                                Pid = pid,
                            };

                            droppedPidsManager.Add(droppedPids);
                            droppedPidsManager.Context.SaveChanges();
                        }
                    }

                    //guardamos las url del dropped
                    if (drop.urls != null)
                    {
                        
                        foreach (var url in drop.urls)
                        {
                            CORE.Cuckoo.DroppedUrls droppedUrls = new CORE.Cuckoo.DroppedUrls
                            {
                                Dropped_Id = dropped.Id,
                                Url = url,
                            };

                            droppedUrlsManager.Add(droppedUrls);
                            droppedUrlsManager.Context.SaveChanges();
                        }
                    }
                                                      
                };
               
                //guardamos cuckoo ststic y sus derivados
                progress = 54;
                status = "Guardando Cuckoo Static...";
                CORE.Cuckoo.CuckooStatic cStatic = new CORE.Cuckoo.CuckooStatic
                {
                    CuckooScan_Id = data.info.id,
                    ImportedDllCount = data.@static.imported_dll_count,
                    PeImphash = data.@static.pe_imphash,
                    PeTimestamp = data.@static.pe_timestamp,
                };

                cuckooStaticManager.Add(cStatic);
                cuckooStaticManager.Context.SaveChanges();

                //Añadimos cuckoo strings
                foreach (var str in data.strings)
                {
                    CORE.Cuckoo.CuckooStrings cStrings = new CORE.Cuckoo.CuckooStrings
                    {
                        CuckooScan_Id = data.info.id,
                        Strings = str,
                    };

                    cuckooStringsManager.Add(cStrings);
                    cuckooStringsManager.Context.SaveChanges();
                }


                //POR CADA PE IMPORT AÑADIMOS UN LINEA
                progress = 56;
                status = "Guardando Static Imports...";
                foreach (var im in data.@static.pe_imports)
                {
                    CORE.Cuckoo.PeImport peImport = new CORE.Cuckoo.PeImport
                    {
                        CuckooStatic_Id = cStatic.Id,
                        Dll = im.dll,

                    };

                    peImportsManager.Add(peImport);
                    peImportsManager.Context.SaveChanges();

                    //dentro de cada pe import añadimos todos los imports relaciondos
                    foreach (var import in im.imports)
                    {
                        CORE.Cuckoo.Imports imp = new CORE.Cuckoo.Imports
                        {
                            PeImport_Id = peImport.Id,
                            Address = import.address,
                            Name = import.name,
                        };

                        importsManager.Add(imp);
                        importsManager.Context.SaveChanges();
                    };

                }
                
                

                //por cada pe export
                progress = 58;
                status = "Guardando Static Exports...";
                foreach (var exp in data.@static.pe_exports)
                {
                    CORE.Cuckoo.PeExport peExport = new CORE.Cuckoo.PeExport
                    {
                        CuckooStatic_Id = cStatic.Id,
                        Dll = exp.dll,

                    };

                    peExportsManager.Add(peExport);
                    peExportsManager.Context.SaveChanges();

                    // por cada pe export añadimo los exports relacionados
                    foreach (var export in exp.exports)
                    {
                        CORE.Cuckoo.Exports exAdd = new CORE.Cuckoo.Exports
                        {
                            PeExport_Id = peExport.Id,
                            Address = export.address,
                            Name = export.name,
                        };

                        exportsManager.Add(exAdd);
                        exportsManager.Context.SaveChanges();

                    };

                }
                
                

                //añadimos los pereources
                progress = 60;
                status = "Guardando Static Resources...";
                foreach (var resource in data.@static.pe_resources)
                {
                    CORE.Cuckoo.PeResource peResource = new CORE.Cuckoo.PeResource
                    {
                        Static_Id = cStatic.Id,
                        Filetype = resource.filetype,
                        Language = resource.language,
                        Name = resource.name,
                        Offset = resource.offset,
                        Size = resource.size,                 

                    };
                    peResourcesManager.Add(peResource);
                    peResourcesManager.Context.SaveChanges();
                }

                


                //guardamos pe sections
                progress = 62;
                status = "Guardando Static Sections...";
                foreach (var section in data.@static.pe_sections)
                {
                    CORE.Cuckoo.PeSection peSection = new CORE.Cuckoo.PeSection
                    {
                        Static_Id = cStatic.Id,
                        Entropy = section.entropy,
                        Name = section.name,
                        SizeOfData = section.size_of_data,
                        VirtualAddress = section.virtual_address,
                        VirtualSize = section.virtual_size,
                    };

                    peSectionsManager.Add(peSection);
                    peSectionsManager.Context.SaveChanges();
                };

                

                //aañdimos static signatures
                progress = 64;
                status = "Guardando Static Signatures...";
                foreach (var sig in data.@static.signature)
                {
                    CORE.Cuckoo.StaticSignature staticSignature = new CORE.Cuckoo.StaticSignature
                    {
                        Static_Id = cStatic.Id,
                        CommonName = sig.common_name,
                        Country = sig.country,
                        Email = sig.email,
                        Locality = sig.locality,
                        Organization = sig.organization,
                        SerialNumber = sig.serial_number
                    };

                    staticSignaturesManager.Add(staticSignature);
                    staticSignaturesManager.Context.SaveChanges();

                };

                

                //añadimos pe keys
                progress = 66;
                status = "Guardando Static Keys...";
                foreach (var key in data.@static.keys)
                {
                    CORE.Cuckoo.StaticKeys staticKeys = new CORE.Cuckoo.StaticKeys
                    {
                        CuckooStatic_Id = cStatic.Id,
                        Keys = key

                    };
                    staticKeysManager.Add(key);
                    staticKeysManager.Context.SaveChanges();
                }

                

                //añadimos cuckoo behavior
                progress = 68;
                status = "Guardando Cuckoo Behavior...";
                CORE.Cuckoo.CuckooBehavior cuckooBehavior = new CORE.Cuckoo.CuckooBehavior
                {
                    CuckooScan_Id = data.info.id
                };

                cuckooBehaviorManager.Add(cuckooBehavior);
                cuckooBehaviorManager.Context.SaveChanges();

                //AÑADIMOS LOS REGISTROS DE DIRECTORY CREATED DENTRO DE BEHAVIOR SUMMARY
                progress = 70;
                status = "Guardando Behavior Summary...";
                foreach (var directory in data.behavior.summary.directory_created)
                {
                    CORE.Cuckoo.BehaviorSummary dirCreated = new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "Directory Created",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(dirCreated);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                foreach (var directory in data.behavior.summary.directory_enumerated)
                {
                    CORE.Cuckoo.BehaviorSummary dirEnum = new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "Directory Enumerated",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(dirEnum);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                foreach (var directory in data.behavior.summary.dll_loaded)
                {
                    CORE.Cuckoo.BehaviorSummary dllLoaded = new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "DLL Loaded",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(dllLoaded);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                foreach (var directory in data.behavior.summary.file_created)
                {
                    CORE.Cuckoo.BehaviorSummary fileCreated = new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "File Created",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(fileCreated);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                foreach (var directory in data.behavior.summary.file_deleted)
                {
                    CORE.Cuckoo.BehaviorSummary fileDeleted = new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "File Deleted",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(fileDeleted);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                foreach (var directory in data.behavior.summary.file_exists)
                {
                    CORE.Cuckoo.BehaviorSummary fileExists= new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "File Exists",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(fileExists);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                foreach (var directory in data.behavior.summary.file_failed)
                {
                    CORE.Cuckoo.BehaviorSummary fileFailed = new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "File Failed",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(fileFailed);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                foreach (var directory in data.behavior.summary.file_opened)
                {
                    CORE.Cuckoo.BehaviorSummary fileOpened = new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "File Opened",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(fileOpened);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                foreach (var directory in data.behavior.summary.file_read)
                {
                    CORE.Cuckoo.BehaviorSummary fileRead = new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "File Read",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(fileRead);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                foreach (var directory in data.behavior.summary.file_written)
                {
                    CORE.Cuckoo.BehaviorSummary fileWritten = new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "File Written",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(fileWritten);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                foreach (var directory in data.behavior.summary.guid)
                {
                    CORE.Cuckoo.BehaviorSummary guid = new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "Guid",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(guid);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                foreach (var directory in data.behavior.summary.regkey_opened)
                {
                    CORE.Cuckoo.BehaviorSummary regKeyOpened = new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "RegKey Opened",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(regKeyOpened);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                foreach (var directory in data.behavior.summary.regkey_read)
                {
                    CORE.Cuckoo.BehaviorSummary regKeyRead = new CORE.Cuckoo.BehaviorSummary
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        Name = "Regkey Read",
                        Strings = directory
                    };

                    BehaviorSummaryManager.Add(regKeyRead);
                    BehaviorSummaryManager.Context.SaveChanges();
                }

                

                //añadimos los registros de process tree
                progress = 74;
                status = "Guardando Behavior ProcessTree...";
                foreach (var process in data.behavior.processtree)
                {
                    CORE.Cuckoo.ProcessTree processTree = new CORE.Cuckoo.ProcessTree
                    {
                        Behavior_Id = cuckooBehavior.Id,
                        CommandLine = process.command_line,
                        FirstSeen = process.first_seen,
                        Pid = process.pid,
                        Ppid = process.ppid,
                        ProcessName = process.process_name,
                        Track = process.track
                    };

                    processTreeManager.Add(processTree);
                    processTreeManager.Context.SaveChanges();
                }

                
                
                //añadimos cuckoo siganture
                progress = 76;
                status = "Guardando Cuckoo Signature...";
                foreach (var sig in data.signatures)
                {
                    CORE.Cuckoo.CuckooSignature cuckooSignature = new CORE.Cuckoo.CuckooSignature
                    {
                        CuckooScan_Id = data.info.id,
                        Description = sig.description,
                        Severity = sig.severity,

                    };

                    cuckooSigantureManager.Add(cuckooSignature);
                    cuckooSigantureManager.Context.SaveChanges();

                    //dentro de sig añadimos los marks relacionados
                   /* progress = 78;
                    status = "Guardando Siganture Marks...";
                    foreach (var mark in sig.marks)
                    {
                        CORE.Cuckoo.Mark markModel = new CORE.Cuckoo.Mark
                        {
                            Siganture_Id = cuckooSignature.Id,
                            Cid = mark.cid,
                            Pid = mark.pid,
                            Type = mark.type,
                            Category = mark.category,
                            Description = mark.description,
                            Ioc = mark.ioc,                          
                        };

                        marksManager.Add(markModel);
                        marksManager.Context.SaveChanges();

                    }*/

                };

                
                                             
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.LogError(ex.Message, ex);
                ErrorMalware(malware);
                Redirect("Index");//guardamos el log si se produce una excepcion

            }

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public async Task GetScreenShotsAsync(int id, int malwareId)
        {
            try
            {
                progress = 82;
                status = "Obteniendo Imagenes...";
                var uploads = Path.Combine(_appEnvironment.WebRootPath, "Uploads/Screenshots/");
                string filename = uploads + id + ".zip";
                WebClient webClient = new WebClient();
                webClient.Headers.Add("Authorization: Bearer VaultApi");
                webClient.DownloadFile(new Uri(CuckooHost + "/tasks/screenshots/" + id), filename);

                ZipFile.ExtractToDirectory(filename, uploads+id);
                System.IO.File.Delete(filename);

                var files = Directory.GetFiles(uploads + id,"*.jpg").Select(Path.GetFileName).ToArray(); ;

                progress = 84;
                status = "Guardando Imagenes...";
                foreach (var img in files)
                {
                    if (!img.EndsWith("_small.jpg"))
                    {
                        CORE.ScreenShot screenShot = new CORE.ScreenShot
                        {
                            Malware_Id = malwareId,
                            PathFile = "/Uploads/Screenshots/" + id + "/" + img
                        };

                        screenShotManager.Add(screenShot);
                        screenShotManager.Context.SaveChanges();
                    }
                }
                   

                    
               
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.LogError(ex.Message, ex);
                Redirect("Index");//guardamos el log si se produce una excepcion
            }
        }

        public async Task StartThreatCrowdAnalysisAsync(int id, string md5)
        {
            try
            {
                //creamos nuevo cliente http
                HttpClient client = new HttpClient();
                client.BaseAddress = new Uri(CuckooHost);
                client.DefaultRequestHeaders.Clear();

                //cremos un unevo request en modo POST
                var request = new HttpRequestMessage(new HttpMethod("GET"), "https://www.threatcrowd.org/searchApi/v2/file/report/?resource=" + md5);

                //mandamos la solictud y recibimos la resuesta
                var response = await client.SendAsync(request);
                progress = 86;
                status = "Obteniendo Información desde ThreatCrwod...";
                //si la respuesta e spositiva Codigo 200
                if (response.IsSuccessStatusCode)
                {
                    //recogemos la respuesta
                    HttpContent content = response.Content;
                    await content.ReadAsStringAsync();
                    //leemos el resultado y lo pasamos a string
                    var result = content.ReadAsStringAsync();
                    string res = result.Result;

                    progress = 88;
                    status = "Guardando Información desde ThreatCrwod...";

                    // del resultado obtenido en string lo pasamos a json y obtenimos el id de la tarea
                    dynamic data = JObject.Parse(res);
                    //registramos la busqueda de threat crowd
                    CORE.ThreatCrowd.ThreatCrowdInfo threatCrowdInfo = new CORE.ThreatCrowd.ThreatCrowdInfo
                    {
                        Malware_Id = id,
                        Type = "File",
                        Permalink = data.permalink
                    };

                    threatCrowdInfoManager.Add(threatCrowdInfo);
                    threatCrowdInfoManager.Context.SaveChanges();
                    //guardamos los scans obtenidos
                    foreach(var scan in data.scans)
                    {
                        CORE.ThreatCrowd.TCScans scans = new CORE.ThreatCrowd.TCScans
                        {
                            ThreatCrowd_Id = threatCrowdInfo.Id,
                            Scan = scan
                        };

                        tCScansManager.Add(scans);
                    }

                    progress = 90;

                    tCScansManager.Context.SaveChanges();
                    //guardamos todos los posibles ips que se hayan podido obtener
                    foreach (var ip in data.ips)
                    {
                        CORE.ThreatCrowd.TCIps tCIps = new CORE.ThreatCrowd.TCIps
                        {
                            ThreatCrowd_Id = threatCrowdInfo.Id,
                            Ip = ip
                        };

                        tCIpsManager.Add(tCIps);
                    }

                    tCIpsManager.Context.SaveChanges();

                    //guardamos todos lo posibles dominios detectados
                    foreach (var domain in data.domains)
                    {
                        CORE.ThreatCrowd.TCDomains tCDomains = new CORE.ThreatCrowd.TCDomains
                        {
                            ThreatCrowd_Id = threatCrowdInfo.Id,
                            Domain = domain
                        };

                        tCDomainsManager.Add(tCDomains);
                    }

                    tCDomainsManager.Context.SaveChanges();

                    //guardamos las referencias si se han obtenido
                    foreach(var reference in data.references)
                    {
                        CORE.ThreatCrowd.TCReferences tCReferences = new CORE.ThreatCrowd.TCReferences
                        {
                            ThreatCrowd_Id = threatCrowdInfo.Id,
                            Reference = reference
                        };
                        tCReferencesManager.Add(tCReferences);
                    }

                    tCReferencesManager.Context.SaveChanges();

                }
                else
                {
                    Console.WriteLine("{0} ({1}) {2}", (int)response.StatusCode, response.ReasonPhrase, response.RequestMessage);
                    Redirect("Index");
                }
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.LogError(ex.Message, ex);
                ErrorMalware(md5);
                Redirect("Index");//guardamos el log si se produce una excepcion
            }

        }

        /// <summary>
        /// Metodo que actualiza la info de Malware 
        /// </summary>
        /// <param name="malware"></param>
        public void UpdateMalware(Malware malware)
        {
            try
            {
                progress = 100;
                status = "Actualizando Registros...";
                var cuckooInfo = cuckooInfoManager.GetByMalwareId(malware.Id);
                var virustotal = vtManager.GetByMalwareId(malware.Id);
                //desde las notas de virustotal y cuckoo haremos la media de estos
                //los que nos dara el nivel del malware
                if (cuckooInfo != null && virustotal != null)
                {

                    var notaVt = virustotal.Positives * virustotal.Total / 100;

                    var notaFinal = notaVt + cuckooInfo.Score / 2;


                    if (notaFinal < 2)
                    {
                        malware.MalwareLevel = Level.Sin_Detecciones;
                        malware.MalwareStatus = Status.Finalizado;
                        malwareManager.Context.SaveChanges();
                    }
                    if(notaFinal > 2 && notaFinal < 5 )
                    {
                        malware.MalwareLevel = Level.Indeterminado;
                        malware.MalwareStatus = Status.Finalizado;
                        malwareManager.Context.SaveChanges();

                    }
                    if (notaFinal > 5 && notaFinal < 7)
                    {
                        malware.MalwareLevel = Level.Sospechoso;
                        malware.MalwareStatus = Status.Finalizado;
                        malwareManager.Context.SaveChanges();
                    }
                    if (notaFinal > 7 && notaFinal < 10)
                    {
                        malware.MalwareLevel = Level.Malicioso;
                        malware.MalwareStatus = Status.Finalizado;
                        malwareManager.Context.SaveChanges();
                    }

                    //preparamos el mensaje de email
                    var from = new List<EmailAddress>();
                    from.Add(new EmailAddress{
                        Address = "proyectofinal.tie@outlook.es",
                        Name = "PoyectoFinal"
                        });
                    var to = new List<EmailAddress>();
                    to.Add(new EmailAddress
                    {
                        Address = User.FindFirstValue(ClaimTypes.Name),
                        Name = User.FindFirstValue(ClaimTypes.Name),
                    });

                    EmailMessage message = new EmailMessage
                    {

                        FromAddresses = from,
                        ToAddresses = to,
                        Subject = "Analisis terminado",
                        Content = "El analisis ha terminado correctamente, lo tiene disponible desde Mis Muestras"                                              
                    };
                    //enviamos el email
                    email.Send(message);
                }
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.LogError(ex.Message, ex);
                ErrorMalware(malware);
                RedirectToAction("Index");
            }
        }

        /// <summary>
        /// Metodo que marca el malware pasado como error
        /// </summary>
        /// <param name="id"id de malware></param>
        public void ErrorMalware(string id)
        {
            var malware = malwareManager.GetByMd5(id);

            try
            {
                malware.MalwareLevel = Level.Sin_Detecciones;
                malware.MalwareStatus = Status.Error;
                malwareManager.Context.SaveChanges();
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.LogError(ex.Message, ex);
            }
        }

        /// <summary>
        /// Metodo que marca el malware pasado como error
        /// </summary>
        /// <param name="malware">malware asociado</param>
        public void ErrorMalware(Malware malware)
        {

            try
            {
                malware.MalwareLevel = Level.Sin_Detecciones;
                malware.MalwareStatus = Status.Error;
                malwareManager.Context.SaveChanges();
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _log.LogError(ex.Message, ex);
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