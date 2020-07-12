using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.Web.Areas.Admin.Models;

namespace ProyectoFinal.Web.Areas.Admin.Controllers
{
    [Authorize(Roles = "Admin")]
    [Area("Admin")]
    [Route("Admin")]
    public class HomeController : Controller
    {
        IMalwareManager malwareManager = null;
        ICommentManager commentManager = null;
        IScreenShotManager screenShotManager = null;
        UserManager<ApplicationUser> _userManager = null;
        ILogger<HomeController> _log = null;

        public HomeController(IMalwareManager malwareManager, ILogger<HomeController> log, ICommentManager commentManager,
            IScreenShotManager screenShotManager, UserManager<ApplicationUser> userManager)
        {
            this.malwareManager = malwareManager;
            this.commentManager = commentManager;
            this.screenShotManager = screenShotManager;
            _userManager = userManager;
            _log = log;
        }
        // GET: Home
        public IActionResult Index()
        {
            try
            {
                AdminPanelViewModel model = new AdminPanelViewModel
                {
                    Malware = malwareManager.GetAll().Select(e => new CORE.Malware
                    {
                        Id = e.Id,
                    }).ToList(),
                    ScreenShot = screenShotManager.GetAll().Select(e => new CORE.ScreenShot
                    {
                        Id = e.Id,
                    }).ToList(),
                    Comment = commentManager.GetAll().Select(e => new CORE.Comment
                    {
                        Id = e.Id,
                    }).ToList(),
                    User = _userManager.Users.Select(e => new CORE.ApplicationUser
                    {
                        Id = e.Id,
                    }).ToList()
                };
                return View(model);
            }
            catch (Exception ex)
            {
                //guardamso log si se produce una excepcion
                _log.LogError(ex.Message, ex);
                return View();
            }
        }
    }
}