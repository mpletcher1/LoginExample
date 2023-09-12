using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
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

        public static TokenValidationParameters CreateTokenValidationParameters(RSACryptoServiceProvider rsa)
        {
            var parameters = new TokenValidationParameters {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                IssuerSigningKey = new RsaSecurityKey(rsa)
            };

            return parameters;
        }

        public static RSAParameters CreateRSAParameters(string publicKey, string type)
        {
            return new RSAParameters(){
                Modulus = WebEncoders.Base64UrlDecode(publicKey),
                Exponent = WebEncoders.Base64UrlDecode(type)
            };
        }
    }
}
