using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;
using ADAMProfile.Models;
using System.Web.Configuration;
using LDAPUtils;

namespace ADAMProfile.Controllers
{
    public class AccountController : Controller
    {
        //
        // GET: /Account/

        public ActionResult Index()
        {
            return RedirectToAction("ChangePassword", "Account");
        }

        //
        // GET: /Account/ChangePassword

        public ActionResult ChangePassword(string environment)
        {
            environment = environment != null ? environment : "";
            var model = new ChangePasswordModel()
            {
                Environment = environment
            };
            return View(model);
        }

        //
        // GET: /Account/ChangePassword

        [HttpPost]
        public ActionResult ChangePassword(ChangePasswordModel model)
        {
            var ADAMUrl = WebConfigurationManager.ConnectionStrings["ADAM"].ConnectionString;
            // Change environments by appending evironment name to the variable name, fx ADAMTest
            if (!String.IsNullOrEmpty(model.Environment) && WebConfigurationManager.ConnectionStrings["ADAM" + model.Environment] != null)
            {
                ADAMUrl = WebConfigurationManager.ConnectionStrings["ADAM" + model.Environment].ConnectionString;
            }
            if (ModelState.IsValid)
            {
                try
                {
                    if (LDAPAccount.ChangePassword(ADAMUrl, model.UserName, model.OldPassword, model.NewPassword))
                    {
                        return RedirectToAction("ChangePasswordSuccess");
                    }
                    else
                    {
                        ModelState.AddModelError("", "The current password is incorrect");
                    }
                }
                catch (Exception ex)
                {
                    ModelState.AddModelError("", ex.Message);
                    ModelState.AddModelError("", "URL:" + ADAMUrl);
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ChangePasswordSuccess

        public ActionResult ChangePasswordSuccess()
        {
            return View();
        }
    }
}
