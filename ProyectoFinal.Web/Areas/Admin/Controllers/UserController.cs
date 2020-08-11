
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
using Microsoft.Extensions.Logging;
using ProyectoFinal.CORE;
using ProyectoFinal.CORE.Contracts;
using ProyectoFinal.DAL;
using ProyectoFinal.Web.Areas.Admin.Models;


namespace ProyectoFinal.Web.Areas.Admin.Controllers
{
    [Authorize(Roles = "Admin")]
    [Area("Admin")]
    public class UserController : Controller
    {
        IUserManager usrManager = null;
        IRoleManager roleManager = null;
        UserManager<ApplicationUser> _userManager = null;
        ILogger<UserController> _log = null;

        public UserController(IUserManager usrManager, IRoleManager roleManager, ILogger<UserController> log, UserManager<ApplicationUser> userManager)
        {
            this.usrManager = usrManager;
            this.roleManager = roleManager;
            _userManager = userManager;
            _log = log;
        }

        /// <summary>
        /// Metodo que muestra la lista de usuarios
        /// </summary>
        /// <returns></returns>
        public IActionResult Index()
        {
            try
            {
                var result = _userManager.Users
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
                _log.LogError(ex.Message, ex);
                return View();
            }

        }

        /// <summary>
        /// Metodo que muestra el form de edicion de un usuario
        /// </summary>
        /// <param name="id"></param>
        /// <returns></returns>
        public IActionResult Edit(string id)
        {
            try
            {

                //Obtenemos los roles y los pasamos a una lista
                var rol = roleManager.GetAll().Select(e => new RolList
                {
                    Id = e.Id.ToString(),
                    Name = e.Name
                }).ToList();

                var li = new List<SelectListItem>();

                foreach (var item in rol)
                {
                    li.Add(new SelectListItem { Text = item.Name, Value = item.Name });
                }

                //obtenemos los datos del usuario por su id
                var user = usrManager.GetByUserId(id);

                var rolUser = _userManager.GetRolesAsync(user).Id;

                var model = new UserEdit
                {
                    ItemList = li,
                    User = new UserList
                    {

                        UserName = user.UserName,
                        Email = user.Email,

                    },
                    Option = rolUser.ToString()
                };

                return View(model);
            }
            catch (Exception ex)
            {
                _log.LogError(ex.Message, ex);
                return RedirectToAction("Index");
            }
            
        }

        /// <summary>
        /// Metodo que guarda los datos editados de un usuario
        /// </summary>
        /// <param name="id">id de usaurio</param>
        /// <param name="model">modelo de useredit</param>
        /// <returns></returns>
        [HttpPost]
        public IActionResult Edit(string id, UserEdit model)
        {
            try
            {

                //obtenemos los datos de usuario y cogemos los datos del form a result
                var result = usrManager.GetByUserId(id);
                result.UserName = model.User.UserName;
                result.Email = model.User.Email;
                // si no se ha introducido una nueva contrseña no hace nada
                if (model.User.Password != null)
                {
                    //creamos un nuevo hasher para encriptar la password
                    var hasher = new PasswordHasher<ApplicationUser>();
                    //desde el hasher mediante la password introducida creamos la password hasheada
                    string hashedNewPassword = hasher.HashPassword(result, model.User.Password);
                    result.PasswordHash = hashedNewPassword;
                }

                

                //incializamos necesario
                var rolUser = _userManager.GetRolesAsync(result).Id;
                var rolUsers = _userManager.GetRolesAsync(result);

                if (model.Option != null)
                {
                    switch (_userManager.GetRolesAsync(result).Result.FirstOrDefault())
                    {
                        case "Admin":
                            //lo eliminamos del rol 
                            _userManager.RemoveFromRoleAsync(result, "Admin").Wait();
                            //añadimos al usuario al rol 
                            _userManager.AddToRoleAsync(result, model.Option).Wait();

                            break;
                        case "Professional":
                            //lo eliminamos del rol 
                            _userManager.RemoveFromRoleAsync(result, "Professional").Wait();
                            //añadimos al usuario al rol 
                            _userManager.AddToRoleAsync(result, model.Option).Wait();
                            break;
                        case "Business":
                            //lo eliminamos del rol 
                            _userManager.RemoveFromRoleAsync(result, "Business").Wait();
                            //añadimos al usuario al rol 
                            _userManager.AddToRoleAsync(result, model.Option).Wait();
                            break;
                        case "Registered":
                            //lo eliminamos del rol 
                            _userManager.RemoveFromRoleAsync(result, "Registered").Wait();
                            //añadimos al usuario al rol 
                            _userManager.AddToRoleAsync(result, model.Option).Wait();
                            break;
                        case "":
                            break;
                    }
                }

                //guardamos los datos
                usrManager.Context.SaveChanges();
                TempData["editado"] = "El usuario se ha editado correctamente";
                _log.LogInformation("Usuario editado correctamente: Id " + id.ToString());
                return RedirectToAction("Index");
            
            }
            catch(Exception ex)
            {
                _log.LogError(ex.Message, ex);
                return View(model);
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
                var user = usrManager.GetByUserId(id);
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
                _log.LogError(e.Message, e);
                Redirect("Error");
            }

            return View();
        }

        ///// <summary>
        ///// Metodo que elimina el usuario pasado
        ///// </summary>
        ///// <param name="id">id de usaurio</param>
        ///// <param name="collection"></param>
        ///// <returns></returns>
        [HttpPost]
        public ActionResult Delete(string id, IFormCollection collection)
        {
            try
            {
                var user = usrManager.GetByUserId(id);
                if (user != null)
                {
                    usrManager.Remove(user);
                    usrManager.Context.SaveChanges();
                }
                TempData["borrado"] = "El usuario se ha borrado correctamente";
                _log.LogInformation("Usuario eliminado correctamente: Id " + id.ToString());
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
