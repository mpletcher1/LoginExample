using BulkyBookWeb.Data;
using BulkyBookWeb.Extensions;
using BulkyBookWeb.Models;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.IdentityModel.Tokens;

using Newtonsoft.Json;

using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using BulkyBookWeb.Security;

namespace BulkyBookWeb.Controllers
{
    public class LoginController : Controller
    {
        private readonly ApplicationDbContext _db;

        private static readonly HttpClient client = new HttpClient();

        //private static string privKeyPath = @"C:\Users\mattp\Dropbox\PC\Documents\private.pem";
        private static string privKeyPath = @"C:\Users\Matt\Documents\private.pem";
        private static string applicationClientID = "urn:gov:gsa:openidconnect.profiles:sp:sso:dept_state:passportwizard";

        public LoginGovMFAHandler MFAHandler = new LoginGovMFAHandler(privKeyPath, applicationClientID);

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
        public IActionResult UserResults(int id, UserAttributes user)
        {
            ViewBag.Message = TempData["Message"];
            ViewBag.Message = user;
            return View();
        }

        /// <summary>
        /// Defult method that Login.gov is configured to return to via the Login.gov sandbox environment.
        /// 
        /// Handles parsing and validating the response token, and resulting actions to retrieve additional info from Login.gov.
        /// </summary>
        /// <returns> Results view following successful login procedure. </returns>
        public IActionResult Result()
        {
            string code = LoginGov_Integration.StringExtensions.GetUrlParameter(Request, "code");
            string state = LoginGov_Integration.StringExtensions.GetUrlParameter(Request, "state");
            string error = LoginGov_Integration.StringExtensions.GetUrlParameter(Request, "error");

            if (MFAHandler.VerifyCodeAndState(code, state))
            {
                var httpMsg = MFAHandler.GetInitialResponseToken(client, code, state);
                if (MFAHandler.VerifyHttpStatusMessage(httpMsg))
                {
                    TokenResult(httpMsg);
                } else
                {
                    Console.WriteLine("Unable to communicate with login endpoint.");
                }
                
                return View("~/Views/Result/Index.cshtml");
            }
            else if (!string.IsNullOrEmpty(error))
            {
                string errorDescription = LoginGov_Integration.StringExtensions.GetUrlParameter(Request, "error_description");
                Console.WriteLine(error);
                TempData["ErrorState"] = error;
                return RedirectToAction("Index", "Login", null);
            } else
            {
                Console.WriteLine("Unknown response from login.gov");
            }
            
            return View();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="response"></param>
        /// <returns></returns>
        public ActionResult TokenResult(HttpResponseMessage response)
        {
            TokenInfo? resp = TokenExtensions.DeserializeResponseToken(response); 

            if (resp != null)
            {
                var idToken = MFAHandler.GetIDToken(resp);
                if (idToken != null)
                {
                    var userAttrsToken = MFAHandler.GetUserAttributesToken(client, resp);
                    return View("~/Views/Result/Index.cshtml");
                }
                else
                {
                    Console.WriteLine("Invalid or no token endpoint reponse");
                    return View("~/Views/Shared/Error.cshtml");
                }
            }
            else
            {
                Console.WriteLine("Invalid token response");
                return View("~/Views/Shared/Error.cshtml");
            }
        }
    }
}
