using System;
using System.Collections.Generic;
using System.Text;
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
            	Console.WriteLine("./ADAMChangePassword list|set LDAP://1.2.3.4:398/CN=Users,DC=example,DC=domain user oldpassword newpassword");
            	Environment.Exit(255);
            }
            
            String type = args[0];
            String url = args[1];
            String user = args[2];
            String oldPassword = args[3];
            String newPassword = args[4];
            bool dryRun = false;
            if(args.Length == 5) {
            	bool.TryParse(args[4], out dryRun);
            }
            
            var adamUri = new Uri(url);
            var userDN = "CN=" + user + "," + adamUri.LocalPath.Substring(1);
            var conn = LdapConnectBind(adamUri, userDN, oldPassword);

            if (type == "list") {
                var search = new SearchRequest
                {
                    DistinguishedName = adamUri.LocalPath.Substring(1),
                    Scope = SearchScope.Subtree,
                    Filter = "(ObjectClass=User)"
                };
                SearchResponse results = (SearchResponse)conn.SendRequest(search);

                foreach(SearchResultEntry item in results.Entries)
                {
                    Console.WriteLine(item.DistinguishedName);
                }
            }
            else if (type == "set")
            {
                bool status = setPassword(conn, userDN, oldPassword, newPassword, true);
                Console.WriteLine("Change password for user {0} on {1}: {2}", adamUri, user, status);
                if (status)
                {
                    Environment.Exit(0);
                }
                else
                {
                    Environment.Exit(1);
                }
            }
        }

        static bool setPassword(LdapConnection connection, string userDN, string oldPassword, string newPassword) {
        	return setPassword(connection, userDN, oldPassword, newPassword, false);
        }

        static LdapConnection LdapConnectBind(Uri url, string user, string password)
        {
            // Create connection without SSL and other security
            LdapConnection connection = new LdapConnection(url.Host + ":" + url.Port);
            if (url.Scheme == "ldap")
            {
                connection.SessionOptions.SecureSocketLayer = false;
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = false;
            }
            else if (url.Scheme == "ldaps")
            {
                connection.SessionOptions.SecureSocketLayer = true;
            }
            else
            {
                throw new Exception("Unknown connection type:" + url.Scheme);
            }

            // Basic bind with user and old password
            NetworkCredential credential = new NetworkCredential(user, password);
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
                    return null;
                }
                else
                {
                    throw;
                }
            }

            return connection;
        }

        static bool setPassword(LdapConnection connection, string userDN, string oldPassword, string newPassword, bool dryRun)
        {
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
                if (ex.Message == "The object does not exist")
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
