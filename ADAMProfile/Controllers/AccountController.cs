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

namespace ADAMProfile.Controllers
{
    public class AccountController : Controller
    {
        //
        // GET: /Account/

        public ActionResult Index()
        {
            return View();
        }

        //
        // GET: /Account/ChangePassword

        public ActionResult ChangePassword()
        {
            return View();
        }

        //
        // GET: /Account/ChangePassword

        [HttpPost]
        public ActionResult ChangePassword(ChangePasswordModel model)
        {
            var ADAMUrl = WebConfigurationManager.ConnectionStrings["ADAM"].ConnectionString;
            if (ModelState.IsValid)
            {
                // ChangePassword will throw an exception rather
                // than return false in certain failure scenarios.
                bool changePasswordSucceeded;
                try
                {
                    changePasswordSucceeded = setPassword(ADAMUrl, model.UserName, model.OldPassword, model.NewPassword);
                }
                catch (Exception)
                {
                    changePasswordSucceeded = false;
                }

                if (changePasswordSucceeded)
                {
                    return RedirectToAction("ChangePasswordSuccess");
                }
                else
                {
                    ModelState.AddModelError("", "The current password is incorrect");
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

        static bool setPassword(string url, string user, string oldPassword, string newPassword)
        {
            var adamUri = new Uri(url);
            var userDN = "CN=" + user + "," + adamUri.LocalPath.Substring(1);

            // Create connection without SSL and other security
            LdapConnection connection = new LdapConnection(adamUri.Host + ":" + adamUri.Port);
            if (adamUri.Scheme == "ldap")
            {
                connection.SessionOptions.SecureSocketLayer = false;
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = false;
            }
            else if (adamUri.Scheme == "ldaps")
            {
                connection.SessionOptions.SecureSocketLayer = true;
            }
            else
            {
                throw new Exception("Unknown connection type:" + adamUri.Scheme);
            }

            // Basic bind with user and old password
            NetworkCredential credential = new NetworkCredential(userDN, oldPassword);
            connection.AuthType = AuthType.Basic;
            try
            {
                connection.Bind(credential);
            }
            catch (LdapException ex)
            {
                // Invalid credentials
                if (ex.ErrorCode == 49)
                {
                    return false;
                }
                else
                {
                    throw;
                }
            }

            // Create change password request
            DirectoryAttributeModification deleteMod = new DirectoryAttributeModification();
            deleteMod.Name = "unicodePwd";
            deleteMod.Add(Encoding.Unicode.GetBytes("\"" + oldPassword + "\""));
            deleteMod.Operation = DirectoryAttributeOperation.Delete;
            DirectoryAttributeModification addMod = new DirectoryAttributeModification();
            addMod.Name = "unicodePwd";
            addMod.Add(Encoding.Unicode.GetBytes("\"" + newPassword + "\""));
            addMod.Operation = DirectoryAttributeOperation.Add;
            ModifyRequest request = new ModifyRequest(userDN, deleteMod, addMod);

            try
            {
                DirectoryResponse response = connection.SendRequest(request);
                return response.ResultCode == 0;
            }
            catch (Exception ex)
            {
                if (ex.Message == "The object does not exist." && adamUri.Scheme == "ldap")
                {
                    throw new Exception("User not allowed to change own password because of missing permission, set dsHeuristics to 0000000001001 on CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,CN=...");
                }
                else
                {
                    throw;
                }
            }
        }

    }
}
