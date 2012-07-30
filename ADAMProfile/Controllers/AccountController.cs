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
using System.Configuration;

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

        public ActionResult ResetTestAccounts()
        {
            var AdminUsers = new Dictionary<string, List<string>>();

            if (!String.IsNullOrEmpty(WebConfigurationManager.AppSettings["AdminUsers"])) {
                var users = WebConfigurationManager.AppSettings["AdminUsers"].Split(',');
                foreach(var item in users) {
                    var user = item.Split(':');
                    if(!AdminUsers.ContainsKey(user[0])) {
                        AdminUsers[user[0]] = new List<string>();
                    }
                    AdminUsers[user[0]] = new List<string>() { user[1], user[2] };
                }
            }
            var test = ConfigurationManager.AppSettings;

            var TestUsers = new Dictionary<string, Dictionary<string, string>>();
            if (!String.IsNullOrEmpty(WebConfigurationManager.AppSettings["TestUsers"])) {
                var users = WebConfigurationManager.AppSettings["TestUsers"].Split(',');
                foreach(var item in users) {
                    var user = item.Split(':');
                    if (!TestUsers.ContainsKey(user[0]))
                    {
                        TestUsers[user[0]] = new Dictionary<string, string>();
                    }
                    TestUsers[user[0]][user[1]] = user[2];
                }
            }

            Console.WriteLine(TestUsers);
            Console.WriteLine(AdminUsers);

            ViewBag.Users = new Dictionary<string,string>();
            foreach (var enviroment in TestUsers)
            {
                if (WebConfigurationManager.ConnectionStrings["ADAM" + enviroment.Key] != null)
                {
                    var ADAMUrl = WebConfigurationManager.ConnectionStrings["ADAM" + enviroment.Key].ConnectionString;
                    var adamUri = new Uri(ADAMUrl);
                    
                    if(AdminUsers.ContainsKey(enviroment.Key)) {
                        foreach (var user in enviroment.Value)
                        {
                            var bindDN = "CN=" + AdminUsers[enviroment.Key][0] + "," + adamUri.LocalPath.Substring(1);
                            var userDN = "CN=" + user.Key + "," + adamUri.LocalPath.Substring(1);
                            var connstr = adamUri.AbsoluteUri.Substring(0, adamUri.AbsoluteUri.Length - adamUri.LocalPath.Length);
                            string status;
                            try
                            {
                                status = LDAPAccount.SetPassword(connstr + "/" + bindDN, AdminUsers[enviroment.Key][1], userDN, user.Value, false).ToString();
                            }
                            catch (DirectoryOperationException ex)
                            {
                                status = ex.Response.ErrorMessage;
                            }
                            catch (Exception ex)
                            {
                                status = ex.Message;
                            }

                            ViewBag.Users[user.Key] = status;
                        }                        
                    }
                }
            }

            return View();
        }
    }
}
