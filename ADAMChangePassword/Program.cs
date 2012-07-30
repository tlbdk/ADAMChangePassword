using System;
using System.Collections.Generic;
using System.Text;
using System.DirectoryServices.Protocols;
using System.Net;
using LDAPUtils;

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
            
            if(args.Length < 4) {
                Console.WriteLine("List Users: ./ADAMChangePassword list LDAP://1.2.3.4:398/CN=adamadmin,CN=Users,DC=example,DC=domain password CN=Users,DC=example,DC=domain");
                Console.WriteLine("Change own password: ./ADAMChangePassword set LDAP://1.2.3.4:398/CN=adamadmin,CN=Users,DC=example,DC=domain oldpassword newpassword [true|false]");
                Console.WriteLine("Set other users password: ./ADAMChangePassword setadmin LDAP://1.2.3.4:398/CN=adamadmin,CN=Users,DC=example,DC=domain adminpassword LDAP://1.2.3.4:398/CN=test,CN=Users,DC=example,DC=domain newpassword [true|false]");
            	Environment.Exit(255);
            }
            String type = args[0];
            String url = args[1];
            String password = args[2];

            var adamUri = new Uri(url);
            var bindDN = adamUri.LocalPath.Substring(1);
            var conn = LDAPAccount.LdapConnectBind(adamUri, bindDN, password);

            if (type == "list")
            {
                
                var searchpath = args[3];

                var search = new SearchRequest
                {
                    DistinguishedName = searchpath,
                    Scope = SearchScope.Subtree,
                    Filter = "(ObjectClass=User)"
                };
                SearchResponse results = (SearchResponse)conn.SendRequest(search);

                foreach (SearchResultEntry item in results.Entries)
                {
                    Console.WriteLine(item.DistinguishedName);
                }
            }
            else if (type == "set")
            {
                var newPassword = args[3];
                bool dryRun = false;
                if(args.Length == 5) {
            	    bool.TryParse(args[4], out dryRun);
                }

                bool status = LDAPAccount.ChangePassword(conn, bindDN, password, newPassword, dryRun);
                Console.WriteLine("Change password for user {0}: {1}", adamUri, status);
                if (status)
                {
                    Environment.Exit(0);
                }
                else
                {
                    Environment.Exit(1);
                }
            }
            else if (type == "setadmin")
            {
                var userDN = args[3];
                var newPassword = args[4];

                bool dryRun = false;
                if (args.Length == 6)
                {
                    bool.TryParse(args[5], out dryRun);
                }

                bool status = LDAPAccount.SetPassword(conn, userDN, newPassword, dryRun);
                Console.WriteLine("Change password for user {0}: {1}", adamUri, status);
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
    }
}
