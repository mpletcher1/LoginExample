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

namespace BulkyBookWeb.Controllers
{
    public class LoginController : Controller
    {
        private readonly ApplicationDbContext _db;

        //static HttpClient client = new HttpClient();

        public class UserInfo
        {
            public string UserName { get; set; }
            public string code { get; set; }
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

        public ActionResult RedirectToAnotherPage()
        {
            var privKeyPath = @"C:\Users\mattp\Dropbox\PC\Documents\private.pem";
            var privKey = System.IO.File.ReadAllText(privKeyPath);
            var tokenStringPlain = "acr_values=http%3A%2F%2Fidmanagement.gov%2Fns%2Fassurance%2Fial%2F1&" +
                        "client_id=urn%3Agov%3Agsa%3Aopenidconnect.profiles%3Asp%3Asso%3Adept_state%3Apassportwizard&" +
                        "nonce=hithereIamnoncenoncenoncenoncenonce&" +
                        "prompt=select_account&" +
                        "redirect_uri=https%3A%2F%2Flocalhost%3A44313%2FLogin&" +
                        "response_type=code&" +
                        "scope=openid+email&" +
                        "state=abcdefghijklmnopabcdefghijklmnop";
            // Create a JWT token with a sample payload
            var tokenHandler = new JwtSecurityTokenHandler();
            var rsaPrivKey = new RSACryptoServiceProvider();
            rsaPrivKey.ImportFromPem(privKey);
            //var key = Convert.FromBase64String("your-secret-key"); // Replace with your secret key
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim("data",
                        "acr_values=http%3A%2F%2Fidmanagement.gov%2Fns%2Fassurance%2Fial%2F1&" +
                        "client_id=urn%3Agov%3Agsa%3Aopenidconnect.profiles%3Asp%3Asso%3Adept_state%3Apassportwizard&" +
                        "nonce=hithereIamnoncenoncenoncenoncenonce&" +
                        "prompt=select_account&" +
                        "redirect_uri=https%3A%2F%2Flocalhost%3A44313%2FLogin&" +
                        "response_type=code&" +
                        "scope=openid+email&" +
                        "state=abcdefghijklmnopabcdefghijklmnop") // Replace with your payload data
                }),
                Expires = DateTime.UtcNow.AddMinutes(10), // Token expiration time
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsaPrivKey), SecurityAlgorithms.RsaSha256Signature)
            };

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
            Console.WriteLine(tokenDescriptor.ToString());
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);
            //var urik = Request.HttpContext.Request.GetDisplayUrl();
            // Redirect to the destination page with the token as a query parameter
            //Response.BufferOutput = true;
            //Response.Redirect("https://idp.int.identitysandbox.gov/openid_connect/authorize?" + tokenStringPlain);
            //ViewBag.ReturnURL = "https://idp.int.identitysandbox.gov/openid_connect/authorize?" + tokenStringPlain;
            return Redirect("https://idp.int.identitysandbox.gov/openid_connect/authorize?" + tokenStringPlain);
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
