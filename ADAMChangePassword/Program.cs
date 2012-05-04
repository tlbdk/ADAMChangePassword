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
            // Password policy: http://www.thegeekispeak.com/archives/134
            
            if(args.Length != 4 && args.Length != 5) {
            	Console.WriteLine("./ADAMChangePassword LDAP://1.2.3.4:398/CN=Users,DC=example,DC=domain user oldpassword newpassword");
            	Environment.Exit(255);
            }
            
            String connection = args[0];
            String user = args[1];
            String oldPassword = args[2];
            String newPassword = args[3];
            bool dryRun = false;
            if(args.Count() == 5) {
            	bool.TryParse(args[4], out dryRun);
            }
            
            bool status;
            
            status = setPassword(connection, user, oldPassword, newPassword, true);
            Console.WriteLine("Change password for user {0} on {1}: {2}", connection, user, status);
            if(status) {
            	Environment.Exit(0);
            } else {
            	Environment.Exit(1);
            }
        }

        static bool setPassword(string url, string user, string oldPassword, string newPassword) {
        	return setPassword(url, user, oldPassword, newPassword, false);
        }
        
        static bool setPassword(string url, string user, string oldPassword, string newPassword, bool dryRun)
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
            	if(!dryRun) {
            		DirectoryResponse response = connection.SendRequest(request);
               		return response.ResultCode == 0;
            	} else {
            		return true;
            	}
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
