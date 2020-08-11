using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using ProyectoFinal.CORE.Contracts.VirusTotal;
using ProyectoFinal.CORE.Cuckoo;
using ProyectoFinal.IFR.Email;
using ProyectoFinal.Web.Models;

namespace ProyectoFinal.Web.Controllers
{
    public class AnalysisController : Controller
    {

        IMalwareManager malwareManager = null;
        IScreenShotManager screenShotManager = null;
        ICommentManager commentManager = null;
        IVirusTotalManager virusTotalManager = null;
        IVirusTotalScanManager virusTotalScanManager = null;
        ICuckooInfoManager cuckooInfoManager = null;
        ICuckooTargetManager cuckooTargetManager = null;
        IThreatCrowdInfoManager threatCrowdInfoManager = null;
        ITCDomainsManager tCDomainsManager = null;
        ITCEmailsManager tCEmailsManager = null;
        ITCHashesManager tCHashesManager = null;
        ITCIpsManager tCIpsManager = null;
        ITCReferencesManager tCReferencesManager = null;
        ITCResolutionManager tCResolutionManager = null;
        ITCScansManager tCScansManager = null;
        ITCSubdomainsManager tCSubdomainsManager = null;
        UserManager<ApplicationUser> _userManager = null;
        ILogger<AnalysisController> _log = null;
        ICuckooStaticManager cuckooStaticManager = null;
        ICuckooStringsManager cuckooStringsManager = null;
        IStaticSignaturesManager staticSignaturesManager = null;
        IStaticKeysManager staticKeysManager = null;
        IPeExportsManager peExportsManager = null;
        IPeImportsManager peImportsManager = null;
        IImportsManager importsManager = null;
        IExportsManager exportsManager = null;
        IPeResourcesManager peResourcesManager = null;
        IPeSectionsManager peSectionsManager = null;
        ICuckooDroppedManager cuckooDroppedManager = null;
        ITargetPidsManager targetPidsManager = null;
        ITargetUrlsManager targetUrlsManager = null;
        IYaraDroppedManager yaraDroppedManager = null;
        IDroppedPidsManager droppedPidsManager = null;
        IDroppedUrlsManager droppedUrlsManager = null;
        ICuckooSigantureManager sigantureManager = null;
        ICuckooBehaviorManager cuckooBehaviorManager = null;
        IBehaviorSummaryManager behaviorSummaryManager = null;
        IProcessTreeManager processTreeManager = null;
        IEmailService email = null;

        public static int malId;

        /// <summary>
        /// Contructor de analysis controller
        /// </summary>
        /// <param name="malwareManager">manager de malware</param>
        /// <param name="log">log</param>
        /// <param name="screenShotManager">amanger de screenshot</param>
        /// <param name="commentManager">manager de comment</param>
        /// <param name="cuckooInfoManager">manager de cuckoo info</param>
        /// <param name="virusTotalManager">manager de virustotal</param>
        /// <param name="threatCrowdInfoManager">manager de threatcrowd</param>
        /// <param name="userManager"></param>
        public AnalysisController(IMalwareManager malwareManager, ILogger<AnalysisController> log, IScreenShotManager screenShotManager,
            ICommentManager commentManager, ICuckooInfoManager cuckooInfoManager, IVirusTotalManager virusTotalManager,
            IThreatCrowdInfoManager threatCrowdInfoManager, UserManager<ApplicationUser> userManager,
            IVirusTotalScanManager virusTotalScanManager, ITCDomainsManager tCDomainsManager, ITCEmailsManager tCEmailsManager,
            ITCHashesManager tCHashesManager, ITCIpsManager tCIpsManager, ITCReferencesManager tCReferencesManager,
            ITCResolutionManager tCResolutionManager, ITCScansManager tCScansManager, ITCSubdomainsManager tCSubdomainsManager,
            ICuckooSigantureManager sigantureManager, ICuckooStaticManager cuckooStaticManager, ICuckooStringsManager cuckooStringsManager,
            IStaticKeysManager staticKeysManager, IPeExportsManager peExportsManager, IPeImportsManager peImportsManager, IImportsManager importsManager,
            IExportsManager exportsManager, IStaticSignaturesManager staticSignaturesManager, IPeResourcesManager peResourcesManager,
            IPeSectionsManager peSectionsManager, ICuckooTargetManager cuckooTargetManager, ICuckooDroppedManager cuckooDroppedManager,
            IDroppedPidsManager droppedPidsManager, IDroppedUrlsManager droppedUrlsManager,
            ITargetPidsManager targetPidsManager, ITargetUrlsManager targetUrlsManager,ICuckooBehaviorManager cuckooBehaviorManager,
            IBehaviorSummaryManager behaviorSummaryManager, IProcessTreeManager processTreeManager, IEmailService email)
        {
            this.malwareManager = malwareManager;
            this.screenShotManager = screenShotManager;
            this.commentManager = commentManager;
            this.virusTotalManager = virusTotalManager;
            this.cuckooInfoManager = cuckooInfoManager;
            this.threatCrowdInfoManager = threatCrowdInfoManager;
            this.virusTotalScanManager = virusTotalScanManager;
            this.tCDomainsManager = tCDomainsManager;
            this.tCEmailsManager = tCEmailsManager;
            this.tCHashesManager = tCHashesManager;
            this.tCIpsManager = tCIpsManager;
            this.tCReferencesManager = tCReferencesManager;
            this.tCResolutionManager = tCResolutionManager;
            this.tCScansManager = tCScansManager;
            this.tCSubdomainsManager = tCSubdomainsManager;
            this.sigantureManager = sigantureManager;
            this.cuckooStaticManager = cuckooStaticManager;
            this.cuckooStringsManager = cuckooStringsManager;
            this.staticSignaturesManager = staticSignaturesManager;
            this.staticKeysManager = staticKeysManager;
            this.peExportsManager = peExportsManager;
            this.peImportsManager = peImportsManager;
            this.importsManager = importsManager;
            this.exportsManager = exportsManager;
            this.peResourcesManager = peResourcesManager;
            this.peSectionsManager = peSectionsManager;
            this.cuckooTargetManager = cuckooTargetManager;
            this.cuckooDroppedManager = cuckooDroppedManager;
            this.droppedPidsManager = droppedPidsManager;
            this.droppedUrlsManager = droppedUrlsManager;
            this.targetPidsManager = targetPidsManager;
            this.targetUrlsManager = targetUrlsManager;
            this.cuckooBehaviorManager = cuckooBehaviorManager;
            this.behaviorSummaryManager = behaviorSummaryManager;
            this.processTreeManager = processTreeManager;
            this.email = email;
            _userManager = userManager;
            _log = log;
        }



        /// <summary>
        /// metodo que devuelve la vista con los detalles del malware
        /// </summary>
        /// <param name="id">md5 del malware</param>
        /// <returns>vista</returns>
        public IActionResult Index(string id)
        {
            try
            {
                //revisamos que el parametro no este vacio
                if (id != null)
                {
                    //desde el parametro obetenmos el malware asociaso
                    var malware = malwareManager.GetByMd5(id);
                    malId = malware.Id;
                    if (malware != null)
                    {
                        if (malware.MalwareStatus != CORE.Status.Finalizado)
                        {
                            return RedirectToAction("Status",malware);
                        }
                        //creamos el modelo de datos de la vista
                        AnalysisIndexViewModel model = new AnalysisIndexViewModel
                        {
                            Malware = malwareManager.GetAll().Where(p => p.MD5 == id).Select(e => new CORE.Malware
                            {
                            Id = malware.Id,
                            User_Id = malware.User_Id,
                            Date = malware.Date,
                            MD5 = malware.MD5,
                            SHA256 = malware.SHA256,
                            FileName = malware.FileName,
                            FilePath = malware.FilePath,
                            Name = malware.Name,
                            MalwareLevel = malware.MalwareLevel,
                            MalwareStatus = malware.MalwareStatus,
                            Url = malware.Url
                        }).FirstOrDefault(),

                            Screenshots = screenShotManager.GetAll().Where(p => p.Malware_Id == malware.Id).Select(e => new CORE.ScreenShot
                            {
                                Id = e.Id,
                                Malware_Id = e.Malware_Id,
                                PathFile = e.PathFile,
                            }).ToList(),

                            Comments = commentManager.GetAll().Where(c => c.Malware_Id == malware.Id).Select(e => new CORE.Comment
                            {
                                Id = e.Id,
                                User = e.User,
                                User_Id = e.User_Id,
                                Malware_Id = e.Malware_Id,
                                TextComment = e.TextComment,
                            }).ToList(),

             
                            VTInfo = virusTotalManager.GetAll().Where(v => v.Malware_Id == malware.Id).Select(e => new CORE.VirusTotal.VirusTotalInfo
                            {
                                Id = e.Id,
                                Malware_Id = e.Malware_Id,
                                Positives = e.Positives,
                                Total = e.Total,
                                MD5 = e.MD5

                            }).SingleOrDefault(),

                            CuckooInfo = cuckooInfoManager.GetAll().Where(v => v.Malware_Id == malware.Id).Select(e => new CORE.Cuckoo.CuckooInfo
                            {
                                Id = e.Id,
                                Malware = e.Malware,
                                Malware_Id = e.Malware_Id,
                                Score = e.Score,
                                Package = e.Package,
                                Category = e.Category,
                                MD5 = e.MD5
                            }).SingleOrDefault(),

                            TCInfo = threatCrowdInfoManager.GetAll().Where(v => v.Malware_Id == malware.Id).Select(e => new CORE.ThreatCrowd.ThreatCrowdInfo
                            {
                                Id = e.Id,
                                Malware_Id = e.Malware_Id,
                                Type = e.Type,
                                Votes = e.Votes,
                                Permalink = e.Permalink
                            }).SingleOrDefault(),

                       
                        };

                        // devolvemos la vista con el modelo de datos
                        return View(model);
                    }
                    else
                    {
                        //
                        return RedirectToAction("Error");
                    }
                }
                else
                {
                    //TODO
                    return RedirectToAction("Index", "Malware");
                }

            }
            catch (Exception ex)
            {
                //guardamso log si se produce una excepcion
                _log.LogError(ex.Message, ex);
                return RedirectToAction("Index", "Malware");
            }
                        
        }

        /// <summary>
        /// Metodo que devuelve la vista con los detalles de virustotal
        /// </summary>
        /// <param name="id">md5 del malware</param>
        /// <returns>vista</returns>
        [Authorize(Roles = "Admin,Business,Professional")]
        public IActionResult VirusTotal(string id)
        {
            try
            {
                //verificamos que el parametro no sea null
                if (id != null)
                {
                    //obtenemos el malware
                    var malware = malwareManager.GetByMd5(id);
                    if (malware != null)
                    {
                        //obtenemos id de virustotal
                        var vtId = virusTotalManager.GetByMalwareId(malware.Id).Id;

                        //creamos el modelo de datos que le pasaremos a la vista
                        AnalysisVTViewModel model = new AnalysisVTViewModel
                        {
                            Malware = malwareManager.GetAll().Where(p => p.MD5 == id).Select(e => new CORE.Malware
                            {
                                Id = malware.Id,
                                User_Id = malware.User_Id,
                                Date = malware.Date,
                                MD5 = malware.MD5,
                                SHA256 = malware.SHA256,
                                FileName = malware.FileName,
                                FilePath = malware.FilePath,
                                Name = malware.Name,
                                MalwareLevel = malware.MalwareLevel,
                                MalwareStatus = malware.MalwareStatus,
                                Url = malware.Url
                            }).FirstOrDefault(),
                            VTScans = virusTotalScanManager.GetAll().Where(e => e.VirusTotal_Id == vtId).Select(e=> new CORE.VirusTotal.VirusTotalScans
                            {
                                Id = e.Id,
                                Name = e.Name,
                                Detected = e.Detected,
                                Result = e.Result,
                                Version = e.Version
                            }).ToList(),
                            VTInfo = virusTotalManager.GetAll().Where(e => e.Malware_Id == malware.Id).Select(e => new CORE.VirusTotal.VirusTotalInfo
                            {
                                Total = e.Total,
                                Positives = e.Positives
                            }).FirstOrDefault()
                           
                        };

                        //devolvemos la vista con el modelo de datos
                        return View(model);
                    }
                    else
                    {
                        //devolvemos error si no se puede obtener el malware
                        return RedirectToAction("Error");
                    }
                }
                else
                {
                    //devolvemos el listado de malwares si es null
                    return RedirectToAction("Index", "Malware");
                }
            }
            catch (Exception ex)
            {
                //guardamso log si se produce una excepcion
                _log.LogError(ex.Message, ex);
                return RedirectToAction("Index", "Malware");
            }          
        }

        /// <summary>
        /// Metodo que devuelve la vista con los detalles de ThreatCrowd
        /// </summary>
        /// <param name="id">md5 de malware</param>
        /// <returns>vista</returns>
        [Authorize(Roles = "Admin,Business,Professional")]
        public IActionResult ThreatCrowd(string id)
        {
            try
            {
                //verificamos que el parametro no sea null
                if (id != null)
                {
                    //obtenemos el malware
                    var malware = malwareManager.GetByMd5(id);
                    if (malware != null)
                    {
                        //obtenemos id de virustotal
                        var tcId = threatCrowdInfoManager.GetByMalwareId(malware.Id).Id;

                        //creamos el modelo de datos que le pasaremos a la vista
                        AnalysisThreatCrowdViewModel model = new AnalysisThreatCrowdViewModel
                        {
                            Malware = malwareManager.GetAll().Where(p => p.MD5 == id).Select(e => new CORE.Malware
                            {
                                Id = malware.Id,
                                User_Id = malware.User_Id,
                                Date = malware.Date,
                                MD5 = malware.MD5,
                                SHA256 = malware.SHA256,
                                FileName = malware.FileName,
                                FilePath = malware.FilePath,
                                Name = malware.Name,
                                MalwareLevel = malware.MalwareLevel,
                                MalwareStatus = malware.MalwareStatus,
                                Url = malware.Url
                            }).FirstOrDefault(),
                            TCDomains = tCDomainsManager.GetAll().Where(p => p.ThreatCrowd_Id == tcId).Select(e => new CORE.ThreatCrowd.TCDomains
                            {
                                Domain = e.Domain
                            }).ToList(),
                            TCEmails = tCEmailsManager.GetAll().Where(p => p.ThreatCrowd_Id == tcId).Select(e => new CORE.ThreatCrowd.TCEmails
                            {
                                Email = e.Email
                            }).ToList(),
                            TCHashes = tCHashesManager.GetAll().Where(p => p.ThreatCrowd_Id == tcId).Select(e => new CORE.ThreatCrowd.TCHashes
                            {
                                Hash = e.Hash
                            }).ToList(),
                            TCIps = tCIpsManager.GetAll().Where(p => p.ThreatCrowd_Id == tcId).Select(e => new CORE.ThreatCrowd.TCIps
                            {
                                Ip = e.Ip
                            }).ToList(),
                            TCSubdomanins = tCSubdomainsManager.GetAll().Where(p => p.ThreatCrowd_Id == tcId).Select(e => new CORE.ThreatCrowd.TCSubdomanins
                            {
                                Subdomain = e.Subdomain
                            }).ToList(),
                            TCReferences = tCReferencesManager.GetAll().Where(p => p.ThreatCrowd_Id == tcId).Select(e => new CORE.ThreatCrowd.TCReferences
                            {
                                Reference = e.Reference
                            }).ToList(),
                            TCResolutions = tCResolutionManager.GetAll().Where(p => p.ThreatCrowd_Id == tcId).Select(e => new CORE.ThreatCrowd.TCResolution
                            {
                                Domain = e.Domain,
                                Ip = e.Ip,
                                LastResolved = e.LastResolved
                            }).ToList(),
                            TCScans = tCScansManager.GetAll().Where(p => p.ThreatCrowd_Id == tcId).Select(e => new CORE.ThreatCrowd.TCScans
                            {
                                Scan = e.Scan
                            }).ToList(),
                            TCInfo = threatCrowdInfoManager.GetAll().Where(p => p.Malware_Id == malware.Id).Select(e => new CORE.ThreatCrowd.ThreatCrowdInfo
                            {
                                Permalink = e.Permalink,
                                Type = e.Type,
                                Votes = e.Votes
                            }).FirstOrDefault(),
                        };

                        //devolvemos la vista con el modelo de datos
                        return View(model);
                    }
                    else
                    {
                        //devolvemos error si no se puede obtener el malware
                        return RedirectToAction("Error");
                    }
                }
                else
                {
                    //devolvemos el listado de malwares si es null
                    return RedirectToAction("Index", "Malware");
                }
            }
            catch (Exception ex)
            {
                //guardamso log si se produce una excepcion
                _log.LogError(ex.Message, ex);
                return RedirectToAction("Index", "Malware");
            }
        }

        /// <summary>
        /// Metodo que deveulve la view con la información de Cuckoo
        /// </summary>
        /// <param name="id">md5 malware</param>
        /// <returns>vista</returns>
        [Authorize(Roles = "Admin,Business,Professional")]
        public IActionResult Cuckoo(string id)
        {
            try
            {
                var malware = malwareManager.GetByMd5(id);
                if (malware != null)
                {
                    var cuckooInfo = cuckooInfoManager.GetByMalwareId(malware.Id);
                    var cuckooStatic = cuckooStaticManager.GetAll().Where(e => e.CuckooScan_Id == cuckooInfo.CuckooScanId).FirstOrDefault();
                    var peImports = peImportsManager.GetAll().Where(e => e.CuckooStatic_Id == cuckooStatic.Id).ToList();
                    var peExports = peExportsManager.GetAll().Where(e => e.CuckooStatic_Id == cuckooStatic.Id).ToList();
                    var imports = peImports.Select(e => e.Id).ToArray();
                    var exports = peExports.Select(e => e.Id).ToArray();
                    var cuckooDropped = cuckooDroppedManager.GetAll().Where(e => e.CuckooScan_Id == cuckooInfo.CuckooScanId).ToList();
                    var droppeds = cuckooDropped.Select(e => e.Id).ToArray();
                    var cuckooTarget = cuckooTargetManager.GetAll().Where(e => e.CuckooScan_Id == cuckooInfo.CuckooScanId).FirstOrDefault();
                    var cuckooBehavior = cuckooBehaviorManager.GetAll().Where(e => e.CuckooScan_Id == cuckooInfo.CuckooScanId).FirstOrDefault();

                    AnalysisCuckooViewModel model = new AnalysisCuckooViewModel
                    {
                        Malware = malware,
                        CuckooInfo = cuckooInfo,
                        Signatures = sigantureManager.GetAll().Where(e => e.CuckooScan_Id == cuckooInfo.CuckooScanId).Select(e => new CORE.Cuckoo.CuckooSignature
                        {
                            Description = e.Description,
                            Severity = e.Severity
                        }).ToList(),
                        CuckooTargetViewModel = new AnalysisCuckooTargetViewModel
                        {
                            CuckooTarget = cuckooTarget,
                            TargetPids = targetPidsManager.GetAll().Where(e => e.Target_Id == cuckooTarget.Id).ToList(),
                            Targeturls = targetUrlsManager.GetAll().Where(e => e.Target_Id == cuckooTarget.Id).ToList(),
                        },
                        CuckooStaticViewModel = new AnalysisCuckooStaticViewModel
                        {
                            CuckooStatic = cuckooStatic,
                            StaticSignature = staticSignaturesManager.GetAll().Where(e => e.Static_Id == cuckooStatic.Id).FirstOrDefault(),
                            CuckooStrings = cuckooStringsManager.GetAll().Where(e => e.CuckooScan_Id == cuckooInfo.CuckooScanId).ToList(),
                            PeExport = peExports,
                            PeImport = peImports,
                            PeResource = peResourcesManager.GetAll().Where(e => e.Static_Id == cuckooStatic.Id).ToList(),
                            PeSection = peSectionsManager.GetAll().Where(e => e.Static_Id == cuckooStatic.Id).ToList(),
                            Imports = importsManager.GetAll().Where(e => imports.Any(id => e.PeImport_Id == id)).ToList(),
                            Exports = exportsManager.GetAll().Where(e => exports.Any(id => e.PeExport_Id == id)).ToList(),
                        },
                        CuckooDroppedViewModel = new AnalysisCuckooDroppedViewModel
                        {
                            CuckooDropped = cuckooDropped,
                            DroppedPids = droppedPidsManager.GetAll().Where(e => droppeds.Any(id => e.Dropped_Id == id)).ToList(),
                            DroppedUrls = droppedUrlsManager.GetAll().Where(e => droppeds.Any(id => e.Dropped_Id == id)).ToList(),
                        },
                        CuckooBehaviorViewModel = new AnalysisCuckooBehaviorViewModel
                        {
                            CuckooBehavior = cuckooBehavior,
                            BehaviorSummary = behaviorSummaryManager.GetAll().Where(e => e.Behavior_Id == cuckooBehavior.Id).ToList(),
                            ProcessTree = processTreeManager.GetAll().Where(e => e.Behavior_Id == cuckooBehavior.Id).ToList()
                        }
                    };
                    return View(model);
                }
                else
                {
                    return RedirectToAction("Index");
                }

            } catch (Exception ex)
            {
                _log.LogError(ex.Message, ex);
                return View();
            }
            
        }

        /// <summary>
        /// Metodo que se encarga de guardar el comentario introducido por el usuario
        /// </summary>
        /// <param name="comment"></param>
        /// <returns></returns>
        [HttpPost]
        [Authorize(Roles = "Admin,Business,Professional,Registered")]
        public IActionResult Comment(IFormCollection comment)
        {
            try
            {
                var text = comment["reply"];
                //creamos el nuevo comentario
                CORE.Comment com = new CORE.Comment
                {
                    Malware_Id = malId,
                    User_Id = _userManager.GetUserId(User),
                    TextComment = text
                };
                //añadiumo y guardamos
                commentManager.Add(com);
                commentManager.Context.SaveChanges();
                TempData["creado"] = "El comentario se ha añadido correctamente";
                _log.LogInformation("Comentario creado correctamente: Id " + com.Id.ToString());
                var md5 = malwareManager.GetById(malId).MD5;

                //preparamos el mensaje de email
                var from = new List<EmailAddress>();
                from.Add(new EmailAddress
                {
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
                    Subject = "Comentario publicado",
                    Content = "El comentario ha sido publicado correctamente"
                };
                //enviamos el email
                email.Send(message);

                return RedirectToAction("Index", "Analysis", new { id = md5 });
            }
            catch (Exception ex)
            {
                //guardamso log si se produce una excepcion
                _log.LogError(ex.Message, ex);
                return View(comment);
            }
            
        }

        /// <summary>
        /// Metodoq ue devuelve la vista error
        /// </summary>
        /// <returns></returns>
        public IActionResult Error()
        {
            return View();
        }

        /// <summary>
        /// metodo que se encarga de descagar el malware que se le pasa
        /// </summary>
        /// <param name="id">md5 del malware</param>
        /// <returns></returns>
        [Authorize(Roles = "Admin,Business,Professional")]
        public IActionResult DownloadMalware(string id)
        {
            try
            {
                var result = malwareManager.GetByMd5(id);
                if (result != null)
                {
                    TempData["downloadSuccess"] = "La muestra se ha descargado correctamente";
                    //return PhysicalFile(result.FilePath, "text/plain", result.FileName);
                    var net = new System.Net.WebClient();
                    var data = net.DownloadData(result.FilePath);
                    var content = new System.IO.MemoryStream(data);
                    var contentType = "APPLICATION/octet-stream";
                    var fileName = result.FileName;
                    return File(content, contentType, fileName);

                }
                else
                {
                    TempData["downloadError"] = "No se encuentra la muestra a descargar";
                    return RedirectToAction("Index", "Analysis", new { id = id });
                }

            }
            catch (Exception ex)
            {
                //guardamso log si se produce una excepcion
                _log.LogError(ex.Message, ex);
                return RedirectToAction("Index","Analysis", new { id = id});
            }
            
        }

        /// <summary>
        /// Metodo que se devulve una vista si el analisis del malware no ha finalizado
        /// </summary>
        /// <param name="malware">malware</param>
        /// <returns>vista</returns>
        [Authorize(Roles = "Admin,Business,Professional,Registered")]
        public IActionResult Status(Malware malware)
        {
            return View(malware);
        }

    }
}
