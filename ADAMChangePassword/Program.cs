using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.Protocols;
using System.Net;

namespace ADAMChangePassword
{
    class Program
    {
        static void Main(string[] args)
        {
            // http://www.informit.com/articles/article.aspx?p=474649&seqNum=4
            // http://stackoverflow.com/questions/6793596/ad-lds-adam-changepassword-over-ssl
            // Setup ADAM to disable requement for SSL when changing the password
            /* 
               Expand the Configuration subtree by double-clicking Configuration and then double-click CN=Configuration,CN={GUID}, where GUID was generated when the configuration of the ADAM instance was performed.
               Expand the CN=Services folder by double-clicking it. Then expand CN=Windows NT by double-clicking it. Highlight and right-click CN=Directory Service and click Properties.
               Scroll down and click dsHeuristics and click Edit.
               Change the 13th character (counting from left) to a 1. The value should be similar to 0000000001001 in the String Attribute Editor. Click OK.
            */
            // http://erlend.oftedal.no/blog/?blogid=7 Setup ADAM SSL

            String connection = "LDAP://192.168.250.35:50000/CN=Users,CN=external,CN=test,DC=apmoller,DC=net";
            //String connection = "LDAPS://192.168.250.35:50636/CN=Users,CN=external,CN=test,DC=apmoller,DC=net";
            String user = "test";
            String oldPassword = "test";
            String newPassword = "test";

            bool status = setPassword(connection, user, oldPassword, newPassword);

            Console.WriteLine("Change password for user {0}: {1}", user, status);
            Console.ReadKey();
            // Do a simple LDAP connect and bind
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
            catch(Exception ex)
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
