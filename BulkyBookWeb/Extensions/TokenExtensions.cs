using BulkyBookWeb.Models;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace BulkyBookWeb.Extensions
{
    public class TokenExtensions
    {
        public static void AssignTokenValue(KeyValuePair<string, object> kv, IDToken tok)
        {
            switch (kv.Key)
            {
                case "sub":
                    tok.sub = kv.Value.ToString();
                    break;
                case "iss":
                    tok.iss = kv.Value.ToString();
                    break;
                case "acr":
                    tok.acr = kv.Value.ToString();
                    break;
                case "nonce":
                    tok.nonce = kv.Value.ToString();
                    break;
                case "aud":
                    tok.aud = kv.Value.ToString();
                    break;
                case "jti":
                    tok.jti = kv.Value.ToString();
                    break;
                case "at_hash":
                    tok.at_hash = kv.Value.ToString();
                    break;
                case "c_hash":
                    tok.c_hash = kv.Value.ToString();
                    break;
                case "exp":
                    tok.exp = Convert.ToInt64(kv.Value);
                    break;
                case "iat":
                    tok.iat = Convert.ToInt64(kv.Value);
                    break;
                case "nbf":
                    tok.nbf = Convert.ToInt64(kv.Value);
                    break;
                default:
                    break;
            }
        }

        /// <summary>
        /// Decodes the response token returned by querying Login.Gov's authentication endpoint, using the provided login.gov public key, key type, and encoded token object. 
        /// 
        /// Upon successful decoding of the token, it is verified using the public key. 
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <param name="loginGovPubKey"></param>
        /// <param name="type"></param>
        /// <returns> An IDToken object containing the Login.Gov response token information. If verification of the token fails, an empty IDToken is returned. </returns>
        public static IDToken DecodeAndVerifyLoginGovResponseToken(TokenInfo token, string loginGovPubKey, string type)
        {
            IDToken resultingToken = new IDToken();
            var idToken = token.id_token;
            string[] tokenParts = idToken.Split('.');

            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(RSACryptoServiceProviderExtensions.CreateRSAParameters(loginGovPubKey, type));
            var validationParameters = RSACryptoServiceProviderExtensions.CreateTokenValidationParameters(rsa);
            var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenParts[0] + '.' + tokenParts[1]));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            if (rsaDeformatter.VerifySignature(hash, WebEncoders.Base64UrlDecode(tokenParts[2])))
            {
                var handler = new JwtSecurityTokenHandler();
                SecurityToken validatedSecurityToken = null;
                handler.ValidateToken(idToken, validationParameters, out validatedSecurityToken);
                JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;

                var dict = validatedJwt.Payload.ToArray();
                IDToken tok = new IDToken();
                foreach (var i in dict)
                {
                    TokenExtensions.AssignTokenValue(i, tok);
                }
                resultingToken = tok;
            }
            return resultingToken;
        }

        /// <summary>
        /// Sets up the request headers and makes a GET request to the Login.gov User Token endpoint. Deserializes the reponse payload and loads it into
        /// a UserAttributes object. 
        /// </summary>
        /// <param name="token"></param>
        /// <param name="userTokenEndpoint"></param>
        /// <param name="client"></param>
        /// <returns> A UserAttributes object representing the possible attributes that are distributed by Login.gov. </returns>
        public static UserAttributes RetrieveLoginGovUserAttributesToken(TokenInfo token, string userTokenEndpoint, HttpClient client)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(token.token_type, token.access_token);
            var response = client.GetAsync(userTokenEndpoint).Result;
            var jsonToken = response.Content.ReadAsStringAsync().Result;
            UserAttributes? resp = JsonConvert.DeserializeObject<UserAttributes>(jsonToken);
            return resp;
        }


        public static string GenerateTokenStringFromParams(string applicationClientID, string tokenRequestEndpointURI, string privKey)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var rsaPrivKey = new RSACryptoServiceProvider();
            rsaPrivKey.ImportFromPem(privKey);

            var randomJTI = LoginGov_Integration.StringExtensions.GetRandomString(20);
                //StringExtensions.GetRandomString(20);
            var expirationTime = ((int)(DateTime.Now.AddMinutes(5).ToUniversalTime() - new DateTime(1970, 1, 1)).TotalSeconds).ToString();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("iss", applicationClientID),
                    new Claim("sub", applicationClientID),
                    new Claim("aud", tokenRequestEndpointURI),
                    new Claim("jti", randomJTI),
                    new Claim("exp", expirationTime)
                }),
                Expires = DateTime.UtcNow.AddMinutes(10), // Token expiration time
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsaPrivKey), SecurityAlgorithms.RsaSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public static TokenInfo DeserializeResponseToken(HttpResponseMessage response)
        {
            var jsonToken = response.Content.ReadAsStringAsync().Result;
            TokenInfo? resp = JsonConvert.DeserializeObject<TokenInfo>(jsonToken);
            return resp;
        }
    }
}
