    using System;
    using System.Security.Cryptography;
    using System.Text.RegularExpressions;

namespace BulkyBookWeb.Extensions
{
    public static class RSACryptoServiceProviderExtensions
    {
        public static void ImportFromPem(this RSACryptoServiceProvider rsa, string pem)
        {
            var pemContents = Regex.Match(pem, @"-----BEGIN RSA PRIVATE KEY-----\r?\n?(.*?)\r?\n?-----END RSA PRIVATE KEY-----", RegexOptions.Singleline).Groups[1].Value;
            var keyBytes = Convert.FromBase64String(pemContents);
            rsa.ImportRSAPrivateKey(keyBytes, out _);
        }
    }
}
