using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace ProyectoFinal.Web.Controllers
{
    public class ScanController : Controller
    {
        // GET: Scan
        public ActionResult Index()
        {
            return View();
        }

        // GET: Scan/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: Scan/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Scan/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(IFormCollection collection)
        {
            try
            {
                // TODO: Add insert logic here

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: Scan/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: Scan/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, IFormCollection collection)
        {
            try
            {
                // TODO: Add update logic here

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: Scan/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: Scan/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                // TODO: Add delete logic here

                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }
    }
}