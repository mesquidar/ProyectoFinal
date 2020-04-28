
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.DAL;
using ProyectoFinal.IFR.Log;
using ProyectoFinal.Web.Areas.Admin.Models;


namespace ProyectoFinal.Web.Areas.Admin.Controllers
{
    [Authorize(Roles = "Admin")]
    [Area("Admin")]
    [Route("Admin/User")]
    public class UserController : Controller
    {
        IUserManager userManager = null;
        IRoleManager roleManager = null;
        ILogEvent _log = null;

        /// <summary>
        /// Constructor del controlador de usuario
        /// </summary>
        /// <param name="userManager">manager de usuario</param>
        /// <param name="profileManager">manager de perfil</param>
        /// <param name="roleManager">manager de rol</param>
        /// <param name="log">log</param>
        public UserController(IUserManager userManager,IRoleManager roleManager, ILogEvent log)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            _log = log;
        }

        /// <summary>
        /// Metodo que muestra la lista de usuarios
        /// </summary>
        /// <returns></returns>
        public ActionResult Index()
        {
            try
            {
                var result = userManager.GetAll()
                .Select(e => new UserList
                {
                    Id = e.Id,
                    UserName = e.UserName,
                    Email = e.Email,
                    PhoneNumber = e.PhoneNumber
                });

                return View(result);
            }
            catch (Exception ex)
            {
                _log.WriteError(ex.Message, ex);
                return View();
            }

        }

        /// <summary>
        /// Metodo que muestra el form de edicion de un usuario
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public ActionResult Edit(string id)
        {
            try
            {
                

                return View();
            }
            catch (Exception ex)
            {
                _log.WriteError(ex.Message, ex);
                return View();
            }
            
        }

        /// <summary>
        /// Metodo que guarda los datos editados de un usuario
        /// </summary>
        /// <param name="id">id de usaurio</param>
        /// <param name="model">modelo de useredit</param>
        /// <returns></returns>
        [HttpPost]
        public ActionResult Edit(string id, UserEdit model)
        {
            try
            {
                
                TempData["editado"] = "El usuario se ha editado correctamente";
                return RedirectToAction("Index");
            }
            catch(Exception ex)
            {
                _log.WriteError(ex.Message, ex);
                return View();
            }
        }

        /// <summary>
        /// Metodo que muestra el usuarioa  elimnar
        /// </summary>
        /// <param name="id">id de usuario</param>
        /// <returns></returns>
        public ActionResult Delete(string id)
        {
            try
            {
                var user = userManager.GetByUserId(id);
                if (user != null)
                {
                    UserList model = new UserList
                    {
                        Id = user.Id,
                        UserName = user.UserName,
                        Email = user.Email
                    };
                    return View(model);
                }
            }
            catch (Exception e)
            {
                _log.WriteError(e.Message, e);
                Redirect("Error");
            }

            return View();
        }

        /// <summary>
        /// Metodo que elimina el usuario pasado
        /// </summary>
        /// <param name="id">id de usaurio</param>
        /// <param name="collection"></param>
        /// <returns></returns>
        [HttpPost]
        public ActionResult Delete(string id, FormCollection collection)
        {
            try
            {
                var user = userManager.GetByUserId(id);
                if (user != null)
                {
                    userManager.Remove(user);
                    userManager.Context.SaveChanges();
                }
                TempData["borrado"] = "El usuario se ha borrado correctamente";
                return RedirectToAction("Index");

            }
            catch (Exception ex)
            {
                _log.WriteError(ex.Message, ex);
                return View();
            }
        }
    }
}
