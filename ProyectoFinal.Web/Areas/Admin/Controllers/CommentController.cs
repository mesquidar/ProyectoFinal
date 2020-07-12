using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Contracts;

namespace ProyectoFinal.Web.Areas.Admin.Controllers
{
    [Authorize(Roles = "Admin")]
    [Area("Admin")]
    public class CommentController : Controller
    {
        ICommentManager commentManager = null;
        ILogger<CommentController> _log = null;

        /// <summary>
        /// Constructor de Comment Controller
        /// </summary>
        /// <param name="commentManager"></param>
        /// <param name="log"></param>
        public CommentController(ICommentManager commentManager, ILogger<CommentController> log)
        {
            this.commentManager = commentManager;
            _log = log;
        }

        /// <summary>
        /// Metodo que carga los comentario en la vista principal
        /// </summary>
        /// <returns>vista</returns>
        public IActionResult Index()
        {
            try
            {
                //obtenemos lso comentarios y los pasamos como modelo a la vista
                var model = commentManager.GetAll().ToList();
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
        /// Metodo que carga los datos de un comentario para poder editarlo
        /// </summary>
        /// <param name="id">id del comentario</param>
        /// <returns>vista</returns>
        public IActionResult Edit(int id)
        {
            try
            {
                //verificamos que el id no este vacio
                if (id != 0)
                {
                    //obtenemos el malware
                    var comment = commentManager.GetById(id);
                    //si elmalware no esta vacio generamos el model
                    if (comment != null)
                    {
                        //creamos modelo para pasarlo a ala vista
                        var model = new Comment
                        {
                            Id = comment.Id,
                            Malware_Id = comment.Malware_Id,
                            Malware = comment.Malware,
                            User = comment.User,
                            User_Id = comment.User_Id,
                            TextComment = comment.TextComment

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
        /// Metodo que guarda las ediciones realizadas en el comentario
        /// </summary>
        /// <param name="id">id de comentario</param>
        /// <param name="model">comentario</param>
        /// <returns>vista</returns>
        [HttpPost]
        public IActionResult Edit(int id,Comment model)
        {
            try
            {
                //verificamos que el id no este vacio
                if (id != 0)
                {
                    //obtenemos el malware
                    var comment = commentManager.GetById(id);
                    //si elmalware no esta vacio generamos el model
                    if (comment != null)
                    {
                        comment.TextComment = model.TextComment;
                        commentManager.Context.SaveChanges();
                        TempData["editado"] = "El comentario se ha editado correctamente";
                        _log.LogInformation("Comentario editado correctamente: Id "+id.ToString());
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
        /// Metodo que pasa el omentario a eliminar
        /// </summary>
        /// <param name="id">id comentario</param>
        /// <returns>vista</returns>
        public IActionResult Delete(int id)
        {
            try
            {
                //obtenemos el comentario
                var comment = commentManager.GetById(id);
                if (comment != null)
                {
                    //creamos modelo de la vista
                    Comment model = new Comment
                    {
                        Id = comment.Id,
                        User = comment.User,
                        User_Id = comment.User_Id,
                        Malware = comment.Malware,
                        Malware_Id = comment.Malware_Id,
                        TextComment = comment.TextComment
                    };
                    return View(model);
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
        /// Metodo que procesa la eliminacion del comentario
        /// </summary>
        /// <param name="id">id comentario</param>
        /// <param name="form">form</param>
        /// <returns>vista</returns>
        [HttpPost]
        public IActionResult Delete(int id, IFormCollection form)
        {
            try
            {
                //obtenemos comentario
                var com = commentManager.GetById(id);
                if (com != null)
                {
                    //eliminamos el comentario y guardamos
                    commentManager.Remove(com);
                    commentManager.Context.SaveChanges();
                }
                TempData["borrado"] = "El comentario se ha borrado correctamente";
                _log.LogInformation("Comentario eliminado correctamente: Id " + id.ToString());
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
