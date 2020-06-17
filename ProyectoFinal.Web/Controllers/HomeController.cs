using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.IFR.Email;
using ProyectoFinal.Web.Models;

namespace ProyectoFinal.Web.Controllers
{
    public class HomeController : Controller
    {
        IMalwareManager malwareManager = null;
        ICommentManager commentManager = null;
        IEmailService email = null;
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger, IMalwareManager malwareManager, ICommentManager commentManager, IEmailService email)
        {
            this.malwareManager = malwareManager;
            this.commentManager = commentManager;
            this.email = email;
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

        [HttpPost]
        public IActionResult Contact(ContactViewModel model)
        {
            try
            {
                //preparamos el mensaje de email
                var from = new List<EmailAddress>();
                from.Add(new EmailAddress
                {
                    Address = "proyectofinal.tie@outlook.es",
                    Name = model.Email
                });
                var to = new List<EmailAddress>();
                to.Add(new EmailAddress
                {
                    Address = "proyectofinal.tie@outlook.es",
                    Name = "PoyectoFinal"
                });

                EmailMessage message = new EmailMessage
                {

                    FromAddresses = from,
                    ToAddresses = to,
                    Subject = model.Subject,
                    Content = model.Message
                };
                //enviamos el email
                email.Send(message);
                TempData["sent"] = "Se ha enviado el correo correctamente";
                return View();
            }
            catch (Exception ex)
            {
                //guardamos el log si se produce una excepcion
                _logger.LogError(ex.Message, ex);
                TempData["error"] = "Error al enviar el mensaje por favor intentalo de nuevo, o contacte con su administrador";
                return View(model);
            }
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
