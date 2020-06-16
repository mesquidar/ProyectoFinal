using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.IFR.Log;
using ProyectoFinal.Web.Areas.Admin.Models;

namespace ProyectoFinal.Web.Areas.Admin.Controllers
{
    [Authorize(Roles ="Admin")]
    [Area("Admin")]
    public class ScreenShotController : Controller
    {
        IScreenShotManager screenShotManager = null;
        IMalwareManager malwareManager = null;
        ILogger<ScreenShotController> _log = null;

        /// <summary>
        /// Constructor de Comment Controller
        /// </summary>
        /// <param name="commentManager"></param>
        /// <param name="log"></param>
        public ScreenShotController(IScreenShotManager screenShotManager, ILogger<ScreenShotController> log, IMalwareManager malwareManager)
        {
            this.malwareManager = malwareManager;
            this.screenShotManager = screenShotManager;
            _log = log;
        }

        /// <summary>
        /// Metodo que carga als imagenes en la vista
        /// </summary>
        /// <returns>vista</returns>
        public IActionResult Index()
        {
            try
            {
                //obtenemos lso comentarios y los pasamos como modelo a la vista
                var model = screenShotManager.GetAll().ToList();
                return View(model);
            }
            catch (Exception ex)
            {
                //guardamso log si se produce una excepcion
                _log.LogError(ex.Message, ex);
                return View();
            }
        }

        /// <summary>
        /// Metodo que carga la imagen a editar
        /// </summary>
        /// <param name="id">id de screenshot</param>
        /// <returns>vista</returns>
        public IActionResult Edit(int id)
        {
            try
            {
                //verificamos que el id no este vacio
                if (id != 0)
                {
                    //obtenemos el malware
                    var img = screenShotManager.GetById(id);
                    //si elmalware no esta vacio generamos el model
                    if (img != null)
                    {
                        //Obtenemos los usuarios y los pasamos a una lista
                        var mal = malwareManager.GetAll().Select(e => new Malware
                        {
                            Id = e.Id,
                            FileName = e.FileName,

                        }).ToList();

                        var malList = new List<SelectListItem>();

                        foreach (var item in mal)
                        {
                            malList.Add(new SelectListItem { Text = item.FileName, Value = item.Id.ToString() });
                        }

                        //creamos modelo para pasarlo a ala vista
                        var model = new ScreenShotEditViewModel
                        {
                            ScreenShot =
                            {
                                Id = img.Id,
                                Malware_Id = img.Malware_Id,
                                Malware = img.Malware,
                                PathFile = img.PathFile
                            },
                            Malware = malList

                        };

                        return View(model);
                    }
                    //si el malware no existe redirigimos a index
                    else
                    {
                        return RedirectToAction("Index");
                    }
                }
                else
                {
                    return RedirectToAction("Index");
                }

            }
            catch (Exception ex)
            {
                //guardamos log si se produce excepcion
                _log.LogError(ex.Message, ex);
                return RedirectToAction("Index");
            }
        }

        /// <summary>
        /// Metodo que elimina la imagen pasada
        /// </summary>
        /// <param name="id">id de screenshot</param>
        /// <param name="model">modelo de screenshoteditviewmodel</param>
        /// <returns>vista</returns>
        [HttpPost]
        public IActionResult Edit(int id,ScreenShotEditViewModel model)
        {
            try
            {
                //verificamos que el id no este vacio
                if (id != 0)
                {
                    //obtenemos el malware
                    var img = screenShotManager.GetById(id);
                    //si elmalware no esta vacio generamos el model
                    if (img != null)
                    {
                        img.Malware_Id = model.ScreenShot.Malware_Id;
                        screenShotManager.Context.SaveChanges();
                        TempData["editado"] = "El comentario se ha editado correctamente";
                        _log.LogInformation("ScreenShot editado correctamente: Id " + id.ToString());
                        return RedirectToAction("Index");
                    }
                    //si el malware no existe redirigimos a index
                    else
                    {
                        return RedirectToAction("Index");
                    }

                }
                else
                {
                    return RedirectToAction("Index");
                }

            }
            catch (Exception ex)
            {
                _log.LogError(ex.Message, ex);
                return RedirectToAction("Index");
            }
        }

        /// <summary>
        /// Metodo que obtiene la imagen a eliminar
        /// </summary>
        /// <param name="id">id de la imagen</param>
        /// <returns>vista</returns>
        public IActionResult Delete(int id)
        {
            try
            {
                //obtenemos el comentario
                var img = screenShotManager.GetById(id);
                if (img != null)
                {
                    //creamos modelo de la vista
                    ScreenShot model = new ScreenShot
                    {
                        Id = img.Id,
                        Malware = img.Malware,
                        Malware_Id = img.Malware_Id,
                        PathFile = img.PathFile
                    };
                    return View(model);
                }
                else
                {
                    return RedirectToAction("Index");
                }
            }
            catch (Exception e)
            {
                _log.LogError(e.Message, e);
                return RedirectToAction("Index");
            }
        }

        /// <summary>
        /// Metodoq ue elimina la imagen pasada
        /// </summary>
        /// <param name="id">id de la imagen</param>
        /// <param name="fomr"></param>
        /// <returns>vista</returns>
        [HttpPost]
        public IActionResult Delete(int id, IFormCollection fomr)
        {
            try
            {
                //obtenemos comentario
                var img = screenShotManager.GetById(id);
                if (img != null)
                {
                    //eliminamos el comentario y guardamos
                    screenShotManager.Remove(img);
                    screenShotManager.Context.SaveChanges();
                }
                TempData["borrado"] = "El comentario se ha borrado correctamente";
                _log.LogInformation("ScreenShot eliminado correctamente: Id " + id.ToString());
                return RedirectToAction("Index");
            }
            catch (Exception ex)
            {
                _log.LogError(ex.Message, ex);
                return View();
            }
        }
    }


}
