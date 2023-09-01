using BulkyBookWeb.Data;
using BulkyBookWeb.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using BulkyBookWeb.Extensions;
using Microsoft.EntityFrameworkCore.Query.Internal;
using Microsoft.Extensions.Hosting;
using System.Security.Principal;
using Microsoft.AspNetCore.Http.Extensions;
using System.Net;
using System.Web;
using NuGet.Protocol;
using NuGet.Protocol.Plugins;
using System.Text.Json;
using Newtonsoft.Json;
using System.Net.Http.Json;
using System.Net.NetworkInformation;
using Microsoft.AspNetCore.WebUtilities;
using System.Text;
using System.Linq;
using System.Net.Http.Headers;
using System.Net.Http;
using Microsoft.CodeAnalysis.Text;

namespace BulkyBookWeb.Controllers
{
    public class LoginController : Controller
    {
        private readonly ApplicationDbContext _db;

        private static readonly HttpClient client = new HttpClient();

        private static string privKeyPath = @"C:\Users\mattp\Dropbox\PC\Documents\private.pem";
        private static string privKey = System.IO.File.ReadAllText(privKeyPath);
        private static string loginGovPubKey = "qRoNXLUugbenQTBHswfiGoKuhKkvUPP6A1GllxEZEAX86FiFSrXr7x_suHZ4cBytsmtFuYGymJZAGTk7DLzvMW0BHZpVtMZ3qvBDsYbNQGN4oLLxIy5-Q1rT1XTZhNkJwaj7gndbKHpQ33FqNQphhdchXB28N9GekDCJKzwEEThhxHkBxhq-hYAkd6rZ2fLiiyd5C4MSO0pMB-E_oGrNdYhCoydaFqVAhojn8am9za-JkjZIE9-Shlv_CQGt0yr91h3agVxeR2aeuZjQmvrhALJUeeJxG4D_Xl-w4v_O6nl0nllKXKHFxjP4ejDdNbht2a1L9BgJoYBjq6pUcWT49w";
        
        public class UserInfo
        {
            public string UserName { get; set; }
            public string code { get; set; }
        }

        //public Random random = new Random();

        

        public LoginController(ApplicationDbContext db)
        {
            _db = db;
        }

        public IActionResult Index()
        {
            return View();
        }

        //GET
        public IActionResult Create()
        {
            return View();
        }

        public void Result()
        {
            var url = Request.GetDisplayUrl();
            var data = Request.QueryString;

            string code = GetUrlParameter(Request, "code");
            string state = GetUrlParameter(Request, "state");
            string error = GetUrlParameter(Request, "error");
            if (!string.IsNullOrEmpty(code) && !string.IsNullOrEmpty(state))
            {
                ExchangeToken(code, state);
            }
            else if (!string.IsNullOrEmpty(error))
            {
                Console.WriteLine(error);   
            } else
            {
                Console.WriteLine("Unknown response from login.gov");
            }
 
        }

        public IDToken HandleTokenInfo(TokenInfo token)
        {
            IDToken resultingToken = new IDToken();
            var idToken = token.id_token;
            string[] tokenParts = idToken.Split('.');

            var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(
                new RSAParameters()
                {
                    Modulus = WebEncoders.Base64UrlDecode(loginGovPubKey),
                    Exponent = WebEncoders.Base64UrlDecode("AQAB")
                });

            var validationParameters = new TokenValidationParameters
            {
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                IssuerSigningKey = new RsaSecurityKey(rsa)
            };

            var sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(tokenParts[0] + '.' + tokenParts[1]));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            if (rsaDeformatter.VerifySignature(hash, WebEncoders.Base64UrlDecode(tokenParts[2])))
            {
                Console.WriteLine("Signature is verified");
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
                // From here need to get the user attributes from User Attr Endpoint 
                // Use this to get it via HTTP GET
                /*
                 * GET https://idp.int.identitysandbox.gov/api/openid_connect/userinfo
                 * Authorization: Bearer (token.access_token)
                 * 
                 */
                // token.access_token will have
            }

            return resultingToken;

        }

        public void RetrieveUserAttributes(TokenInfo token)
        {
            var url = "https://idp.int.identitysandbox.gov/api/openid_connect/userinfo?";
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(token.token_type, token.access_token);
            var response = client.GetAsync(url).Result;
            //Parse JSON response here
            Console.WriteLine(response);
            var jsonToken = response.Content.ReadAsStringAsync().Result;
            UserAttributes? resp = JsonConvert.DeserializeObject<UserAttributes>(jsonToken);
            Console.WriteLine(resp);
            ViewBag.UserAttributes = resp;
        }

       
        // Want to change this to IActionResult to display the resulting info in the
        // 'Results' View.
        public void TokenResult(HttpResponseMessage response)
        {

            var options = new JsonSerializerSettings
            {
                MetadataPropertyHandling = MetadataPropertyHandling.Ignore,
                DateParseHandling = DateParseHandling.None,
            };
            //var url = Request.GetDisplayUrl();
            var jsonToken = response.Content.ReadAsStringAsync().Result;
            TokenInfo? resp = JsonConvert.DeserializeObject<TokenInfo>(jsonToken);

            if (resp != null)
            {
                ViewBag.TokenInfo = resp;
                var idToken = HandleTokenInfo(resp);
                if (idToken != null)
                {
                    ViewBag.IDToken = idToken;
                    RetrieveUserAttributes(resp);
                    //return View("~/Views/Result/Index.cshtml");
                    //return View();
                }
                else
                {
                    Console.WriteLine("Invalid or no token endpoint reponse");
                    //return View("~/Views/Shared/Error.cshtml");
                }
            }
            else
            {
                Console.WriteLine("Invalid token response");
                //return View("~/Views/Shared/Error.cshtml");
            }
            
  
        }

        [HttpPost]
        [IgnoreAntiforgeryToken]
        public async void ExchangeToken(string code, string state)
        {
            var clientID = "urn:gov:gsa:openidconnect.profiles:sp:sso:dept_state:passportwizard";
            var tokenEndpoint = "https://idp.int.identitysandbox.gov/api/openid_connect/token";
            var tokenHandler = new JwtSecurityTokenHandler();
            var rsaPrivKey = new RSACryptoServiceProvider();
            rsaPrivKey.ImportFromPem(privKey);
            client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/json");

            var randomJTI = StringExtensions.GetRandomString(20);
            var expirationTime = (int)(DateTime.Now.AddMinutes(5).ToUniversalTime() - new DateTime(1970, 1, 1)).TotalSeconds;
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("iss", clientID),
                    new Claim("sub", clientID),
                    new Claim("aud", tokenEndpoint), 
                    new Claim("jti", "udsahuidhauidsaduaduiaduisadhiauudiwqduq12321312sdas"), 
                    new Claim("exp", expirationTime.ToString())
                }),
                Expires = DateTime.UtcNow.AddMinutes(10), // Token expiration time
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsaPrivKey), SecurityAlgorithms.RsaSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            var client_assertion = "client_assertion=" + tokenString + "&";
            var client_assertion_type = "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&";
            var clientCode = "code=" + code + "&";
            var grant_type = "grant_type=authorization_code";
            var combinedClientInfoStr = client_assertion + client_assertion_type + clientCode + grant_type;
            // Redirect to the destination page with the token as a query parameter
            var contentStr = new StringContent(""); //Need empty content string here, as we are only sending URI with params.
            var response = await client.PostAsync("https://idp.int.identitysandbox.gov/api/openid_connect/token?" + combinedClientInfoStr, contentStr);
            if (response.IsSuccessStatusCode)
            {
                TokenResult(response);
            }
            else
            {
                // Handle error response
                Console.WriteLine(response.ToString());
            }
        }


        private string GetUrlParameter(HttpRequest request, string paramName)
        {
            string result = "";
            var urlParams = HttpUtility.ParseQueryString(Request.QueryString.ToString());
            if (urlParams.AllKeys.Contains(paramName))
            {
                result = urlParams.Get(paramName);
            }
            return result;
        }
    }
}
