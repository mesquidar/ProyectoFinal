using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.CORE.Contracts.Cuckoo;
using ProyectoFinal.CORE.Contracts.ThreatCrowd;
using ProyectoFinal.CORE.Contracts.VirusTotal;
using ProyectoFinal.IFR.Log;
using ProyectoFinal.Web.Models;


// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace ProyectoFinal.Web.Controllers
{
    public class AnalysisController : Controller
    {

        IMalwareManager malwareManager = null;
        IScreenShotManager screenShotManager = null;
        ICommentManager commentManager = null;
        IVirusTotalManager virusTotalManager = null;
        ICuckooInfoManager cuckooInfoManager = null;
        IThreatCrowdInfoManager threatCrowdInfoManager = null;
        UserManager<ApplicationUser> _userManager = null;
        ILogEvent _log = null;

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
        public AnalysisController(IMalwareManager malwareManager, ILogEvent log, IScreenShotManager screenShotManager,
            ICommentManager commentManager, ICuckooInfoManager cuckooInfoManager, IVirusTotalManager virusTotalManager,
            IThreatCrowdInfoManager threatCrowdInfoManager, UserManager<ApplicationUser> userManager)
        {
            this.malwareManager = malwareManager;
            this.screenShotManager = screenShotManager;
            this.commentManager = commentManager;
            this.virusTotalManager = virusTotalManager;
            this.cuckooInfoManager = cuckooInfoManager;
            this.threatCrowdInfoManager = threatCrowdInfoManager;
            _userManager = userManager;
            _log = log;
        }

        // GET: /<controller>/
        public IActionResult Index(string md5)
        {
            try
            {
                if (md5 != null)
                {
                    var malware = malwareManager.GetByMd5(md5);
                    if (malware != null)
                    {

                        AnalysisIndexViewModel model = new AnalysisIndexViewModel
                        {
                            Malware =
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
                        },

                            Screenshots = screenShotManager.GetAll().Where(p => p.Malware_Id == malware.Id).Select(e => new CORE.ScreenShot
                            {
                                Id = e.Id,
                                Malware_Id = e.Malware_Id,
                                PathFile = e.PathFile,
                            }).ToList(),

                            Comments = commentManager.GetAll().Where(c => c.Malware_Id == malware.Id).Select(e => new CORE.Comment
                            {
                                Id = e.Id,
                                User_Id = e.User_Id,
                                Malware_Id = e.Malware_Id,
                                TextComment = e.TextComment,
                            }).ToList(),

                            Result =
                        {
                            VTInfo = virusTotalManager.GetAll().Where(v => v.Malware_Id == malware.Id).Select(e => new CORE.VirusTotal.VirusTotalInfo
                            {
                                Id = e.Id,
                                Malware_Id = e.Malware_Id,
                                Positives = e.Positives,
                                Total = e.Total,

                            }).SingleOrDefault(),

                            CuckooInfo = cuckooInfoManager.GetAll().Where(v => v.Malware_Id == malware.Id).Select(e => new CORE.Cuckoo.CuckooInfo
                            {
                                Id = e.Id,
                                CuckooScanId = e.CuckooScanId,
                                Malware_Id = e.Malware_Id,
                                Score = e.Score,
                                Package = e.Package,
                                Category = e.Category,
                            }).SingleOrDefault(),

                            TCInfo = threatCrowdInfoManager.GetAll().Where(v => v.Malware_Id == malware.Id).Select(e => new CORE.ThreatCrowd.ThreatCrowdInfo
                            {
                                Id = e.Id,
                                Malware_Id = e.Malware_Id,
                                Type = e.Type,
                                Votes = e.Votes,
                                Permalink = e.Permalink
                            }).SingleOrDefault(),

                        }

                        };

                        return View(model);
                    }
                    else
                    {
                        return RedirectToAction("Error");
                    }
                }
                else
                {
                    //TODO
                    return RedirectToAction("Error");
                }

            }
            catch (Exception ex)
            {
                //guardamso log si se produce una excepcion
                _log.WriteError(ex.Message, ex);
                return View();
            }
                        
        }

        public IActionResult VirusTotal()
        {
            return View();
        }

        public IActionResult ThreatCrowd()
        {
            return View();
        }

        public IActionResult Cuckoo()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Comment(Comment comment)
        {
            try
            {
                //creamos el nuevo comentario
                CORE.Comment com = new CORE.Comment
                {
                    Malware_Id = comment.Malware_Id,
                    User_Id = _userManager.GetUserId(User),
                    TextComment = comment.TextComment
                };
                //añadiumo y guardamos
                commentManager.Add(comment);
                commentManager.Context.SaveChanges();
                TempData["creado"] = "El comentario se ha añadido correctamente";
                return View();
            }
            catch (Exception ex)
            {
                //guardamso log si se produce una excepcion
                _log.WriteError(ex.Message, ex);
                return View(comment);
            }
            
        }

        public IActionResult Error()
        {
            return View();
        }

    }
}
