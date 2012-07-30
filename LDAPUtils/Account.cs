using System;
using System.Collections.Generic;
using System.Text;
using System.DirectoryServices.Protocols;
using System.Net;

namespace LDAPUtils
{
    public static class LDAPAccount
    {
        public static LdapConnection LdapConnectBind(Uri url, string user, string password)
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
                    throw new Exception(String.Format("Invalid credentials: {0}, {1}", user, password));
                }
                else
                {
                    throw;
                }
            }

            return connection;
        }

        public static bool SetPassword(String url, string adminPassword, string userDN, string newPassword, bool dryRun = false)
        {
            var adamUri = new Uri(url);
            var bindDN = adamUri.LocalPath.Substring(1);
            var conn = LDAPAccount.LdapConnectBind(adamUri, bindDN, adminPassword);
            return SetPassword(conn, userDN, newPassword, dryRun);
        }

        public static bool SetPassword(LdapConnection connection, string userDN, string newPassword, bool dryRun = false)
        {
            DirectoryAttributeModification addMod = new DirectoryAttributeModification();
            addMod.Name = "unicodePwd";
            addMod.Add(Encoding.Unicode.GetBytes("\"" + newPassword + "\""));
            addMod.Operation = DirectoryAttributeOperation.Replace;
            ModifyRequest request = new ModifyRequest(userDN, addMod);

            try
            {
                if (!dryRun)
                {
                    DirectoryResponse response = connection.SendRequest(request);
                    return response.ResultCode == 0;
                }
                else
                {
                    return true;
                }
            }
            catch (DirectoryOperationException ex)
            {
                if (ex.Response.ErrorMessage.StartsWith("0000052D"))
                {
                    throw new Exception("Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain.");
                }
                else
                {
                    throw;
                }
            }
        }

        public static bool ChangePassword(String url, string user, string oldPassword, string newPassword, bool dryRun = false)
        {
            var adamUri = new Uri(url);
            var bindDN = "CN=" + user + "," + adamUri.LocalPath.Substring(1);
            var conn = LDAPAccount.LdapConnectBind(adamUri, bindDN, oldPassword);
            return ChangePassword(conn, bindDN, oldPassword, newPassword, dryRun);
        }

        public static bool ChangePassword(LdapConnection connection, string userDN, string oldPassword, string newPassword, bool dryRun = false)
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
                if (!dryRun)
                {
                    DirectoryResponse response = connection.SendRequest(request);
                    return response.ResultCode == 0;
                }
                else
                {
                    return true;
                }
            }
            
            catch (DirectoryOperationException ex)
            {
                if (ex.Response.ErrorMessage.StartsWith("0000052D"))
                {
                    throw new Exception("Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain.");
                }
                // TODO: Convert to DirectoryOperationException and use better match to give the dsHeuristics exception
                else if (ex.Message == "The object does not exist")
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
