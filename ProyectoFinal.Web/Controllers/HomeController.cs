using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.Web.Models;

namespace ProyectoFinal.Web.Controllers
{
    public class HomeController : Controller
    {
        IMalwareManager malwareManager = null;
        ICommentManager commentManager = null;
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger, IMalwareManager malwareManager, ICommentManager commentManager)
        {
            this.malwareManager = malwareManager;
            this.commentManager = commentManager;
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public IActionResult Contact()
        {
            return View();
        }

        public IActionResult Faq()
        {
            return View();
        }

        public IActionResult Legal()
        {
            return View();
        }

        public IActionResult MyComments()
        {
            try
            {
                var model = commentManager.GetAll().Where(e => e.User_Id == User.FindFirstValue(ClaimTypes.NameIdentifier)).ToList();
                if (model != null)
                {
                    return View(model);
                }
                else
                {
                    return View();
                }
                
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                return RedirectToAction("Index");
            }
        }

        public IActionResult MyMalware()
        {
            try
            {
                var model = malwareManager.GetAll().Where(e => e.User_Id == User.FindFirstValue(ClaimTypes.NameIdentifier)).ToList();
                if (model!= null)
                {
                    return View(model);
                }
                else
                {
                    return View();
                }
                
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex);
                return RedirectToAction("Index");
            }
        }
    }
}
