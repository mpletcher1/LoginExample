using BulkyBookWeb.Data;
using BulkyBookWeb.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using BulkyBookWeb.Extensions;

namespace BulkyBookWeb.Controllers
{
    public class LoginController : Controller
    {
        private readonly ApplicationDbContext _db;

        public LoginController(ApplicationDbContext db)
        {
            _db = db;
        }

        public IActionResult Index()
        {
            IEnumerable<Category> objCategoryList = _db.Categories;
            return View(objCategoryList);
        }

        //GET
        public IActionResult Create()
        {
            return View();
        }

        public ActionResult RedirectToAnotherPage()
        {
            string CLIENT_ID = "7777";
            var privKeyPath = @"C:\Users\mattp\Dropbox\PC\Documents\private.pem";
            var privKey = System.IO.File.ReadAllText(privKeyPath);

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
                        "acr_values=http://idmanagement.gov/ns/assurance/ial/1&\r\n  " +
                        "client_id=7777&\r\n  " +
                        "nonce=hithereIamnoncenoncenoncenoncenonce&\r\n  " +
                        "prompt=select_account&\r\n  " +
                        "redirect_uri=https://localhost:44313/&\r\n  " +
                        "response_type=code&\r\n  " +
                        "scope=openid+email&\r\n  " +
                        "state=abcdefghijklmnopabcdefghijklmnop") // Replace with your payload data
                }),
                Expires = DateTime.UtcNow.AddMinutes(10), // Token expiration time
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsaPrivKey), SecurityAlgorithms.RsaSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            // Redirect to the destination page with the token as a query parameter
            return Redirect("https://idp.int.identitysandbox.gov/openid_connect/authorize?/" + tokenString);
            //return Json(new { Token = tokenString });
        }



    }
}
