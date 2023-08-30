﻿using BulkyBookWeb.Data;
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

namespace BulkyBookWeb.Controllers
{
    public class LoginController : Controller
    {
        private readonly ApplicationDbContext _db;

        private static readonly HttpClient client = new HttpClient();

        public class UserInfo
        {
            public string UserName { get; set; }
            public string code { get; set; }
        }

        //public Random random = new Random();

        public static string GetRandomString(int len)
        {
            var r = new Random();
            var str = new String(Enumerable.Range(0, len).Select(n => (Char)(r.Next(32, 127))).ToArray());
            return str;
        }

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


        public void TokenResult()
        {
            var url = Request.GetDisplayUrl();
            //var data = Request.HasJsonContentType();
            if (Request.HasJsonContentType())
            {
                var data = Request.Body.ToJson();
            }
        }

        [HttpPost]
        [IgnoreAntiforgeryToken]
        private async void ExchangeToken(string code, string state)
        {
            var clientID = "urn:gov:gsa:openidconnect.profiles:sp:sso:dept_state:passportwizard";
            var tokenEndpoint = "https://idp.int.identitysandbox.gov/api/openid_connect/token";
            var privKeyPath = @"C:\Users\mattp\Dropbox\PC\Documents\private.pem";
            var privKey = System.IO.File.ReadAllText(privKeyPath);
            var tokenHandler = new JwtSecurityTokenHandler();
            var rsaPrivKey = new RSACryptoServiceProvider();
            rsaPrivKey.ImportFromPem(privKey);

            client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/json");
           

            var randomJTI = GetRandomString(20);
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

            Console.WriteLine(tokenDescriptor.ToString());
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            var client_assertion = "client_assertion=" + tokenString + "&";
            var client_assertion_type = "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&";
            var clientCode = "code=" + code + "&";
            var grant_type = "grant_type=authorization_code";
            var combinedClientInfoStr = client_assertion + client_assertion_type + clientCode + grant_type;
            //var urik = Request.HttpContext.Request.GetDisplayUrl();
            // Redirect to the destination page with the token as a query parameter
            //Response.BufferOutput = true;

            string message = JsonSerializer.Serialize(combinedClientInfoStr);
            byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
            var content = new ByteArrayContent(messageBytes);
            content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");

            //var response = client.PostAsync(loggedUser.serverUrl + "/api/v2/job", content).Result;
            
            
            var dict = new Dictionary<string, string>{
                //{"client_assertion", client_assertion},
                {"client_assertion_type", client_assertion_type },
                {"code", clientCode},
                {"grant_type", grant_type}
            };

            var contentStr = new StringContent("");
            //var content = new FormUrlEncodedContent(dict);
            var response = await client.PostAsync("https://idp.int.identitysandbox.gov/api/openid_connect/token", content);
            //Response.Redirect("https://idp.int.identitysandbox.gov/api/openid_connect/token" + combinedClientInfoStr);
            Console.WriteLine(response.ToString());
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

        public void RedirectToAnotherPage()
        {
            var client = new HttpClient();
            
            var tokenStringPlain = "acr_values=http%3A%2F%2Fidmanagement.gov%2Fns%2Fassurance%2Fial%2F1&" +
                        "client_id=urn%3Agov%3Agsa%3Aopenidconnect.profiles%3Asp%3Asso%3Adept_state%3Apassportwizard&" +
                        "nonce=hithereIamnoncenoncenoncenoncenonce&" +
                        "prompt=select_account&" +
                        "redirect_uri=https%3A%2F%2Flocalhost%3A44313%2FLogin&" +
                        "response_type=code&" +
                        "scope=openid+email&" +
                        "state=abcdefghijklmnopabcdefghijklmnop";
            // Create a JWT token with a sample payload
            
            //var key = Convert.FromBase64String("your-secret-key"); // Replace with your secret key
            

            /*
            expect(WebMock).to have_requested(:post, "#{root_url}/oauth/authenticate").
                with(
                  body: hash_including(
                    {
                        'username' => username,
                      'password' => password,
                      'grant_type' => 'implicit',
                      'response_type' => 'token',
                      'client_id' => client_id,
                      'scope' => 'ivs.ippaas.apis',
                    },
                  ),
                  headers:
                    {
                        'Content-Type': 'application/json; charset=utf-8',
                  },
                )
            end
            */
            
            //ViewBag.ReturnURL = "https://idp.int.identitysandbox.gov/openid_connect/authorize?" + tokenStringPlain;
           
            //var result = client.PostAsync("https://idp.int.identitysandbox.gov/openid_connect/authorize?" + tokenStringPlain, "application/x-www-form-urlencoded");
            //Console.WriteLine(result);

            //Redirect("https://idp.int.identitysandbox.gov/openid_connect/authorize?" + tokenStringPlain);
            //response.ToString();
            
           // Response.OnCompleted(getResponseInfo());
            //return Response.;
            //return Json(new { Token = tokenString });
        }

        /*

        static async Task<Uri> RedirectLoginPageAsync(string uri, string jwtInfo)
        {
            HttpResponseMessage response = await client.PostAsJsonAsync(
                "api/products", product);
            response.EnsureSuccessStatusCode();

            // return URI of the created resource.
            return response.Headers.Location;
        }

        static async Task<UserInfo> GetProductAsync(string path)
        {
            Product product = null;
            HttpResponseMessage response = await client.GetAsync(path);
            if (response.IsSuccessStatusCode)
            {
                product = await response.Content.ReadAsAsync<Product>();
            }
            return product;
        }

        
        public Func<string,Task> getResponseInfo()
        {
            return 
        }

        */


    }
}