using BulkyBookWeb.Extensions;
using BulkyBookWeb.Models;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace BulkyBookWeb.Security
{
    public class LoginGovMFAHandler
    {

        //private static string privKeyPath = @"C:\Users\mattp\Dropbox\PC\Documents\private.pem";
        private static string privKeyPath = @"C:\Users\Matt\Documents\private.pem";
        private static string privKey = System.IO.File.ReadAllText(privKeyPath);
        private static string loginGovPubKey = "qRoNXLUugbenQTBHswfiGoKuhKkvUPP6A1GllxEZEAX86FiFSrXr7x_suHZ4cBytsmtFuYGymJZAGTk7DLzvMW0BHZpVtMZ3qvBDsYbNQGN4oLLxIy5-Q1rT1XTZhNkJwaj7gndbKHpQ33FqNQphhdchXB28N9GekDCJKzwEEThhxHkBxhq-hYAkd6rZ2fLiiyd5C4MSO0pMB-E_oGrNdYhCoydaFqVAhojn8am9za-JkjZIE9-Shlv_CQGt0yr91h3agVxeR2aeuZjQmvrhALJUeeJxG4D_Xl-w4v_O6nl0nllKXKHFxjP4ejDdNbht2a1L9BgJoYBjq6pUcWT49w";
        private static string? applicationClientID;
        private static readonly string clientAssertionType = "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer";
        private static string loginGovKeyType = "AQAB";

        public readonly string userInfoEndpointURI = "https://idp.int.identitysandbox.gov/api/openid_connect/userinfo?";
        public readonly string tokenRequestEndpointURI = "https://idp.int.identitysandbox.gov/api/openid_connect/token";

        public LoginGovMFAHandler(string privateKeyPath, string appClientID)
        {
            privKeyPath = privateKeyPath;
            privKey = System.IO.File.ReadAllText(privKeyPath);
            applicationClientID = appClientID;
        }

        /// <summary>
        /// Creates a parametrized URI containing the required fields to POST to Login.gov, and retrieves the response.
        /// </summary>
        /// <param name="code"></param>
        /// <param name="state"></param>
        /// <returns> 
        /// On success, an encoded HttpResponseMessage containing the response token from Login.gov. 
        /// On failure, an HttpResponseMessage containing HttpStatusCode.NotAcceptable.
        /// </returns>
        [HttpPost]
        [IgnoreAntiforgeryToken]
        public HttpResponseMessage GetInitialResponseToken(HttpClient client, string code, string state)
        {
            // should look like this: return IntialRespoonseTokenRetriever.Retrieve(client, code, state)
            var tokenString = TokenExtensions.GenerateTokenStringFromParams(applicationClientID, tokenRequestEndpointURI, privKey);

            var client_assertion = LoginGov_Integration.StringExtensions.GenerateParametrizedURLEntry("client_assertion", tokenString);
            var client_assertion_type = LoginGov_Integration.StringExtensions.GenerateParametrizedURLEntry("client_assertion_type", clientAssertionType);
            var clientCode = LoginGov_Integration.StringExtensions.GenerateParametrizedURLEntry("code", code);
            var grant_type = LoginGov_Integration.StringExtensions.GenerateParametrizedURLEntry("grant_type", "authorization_code", true); //Last URI entry cannot have "&" on the end.
            var combinedClientInfoStr = client_assertion + client_assertion_type + clientCode + grant_type;

            // Redirect to the destination page with the token as a query parameter
            var contentStr = new StringContent(""); //Need empty content string here, as we are only sending URI with params, no body.
            client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/json");
            var response = client.PostAsync(tokenRequestEndpointURI + "?" + combinedClientInfoStr, contentStr).Result;
            if (response.IsSuccessStatusCode)
                return response;
            else
                return new HttpResponseMessage(HttpStatusCode.NotAcceptable);
        }


        public IDToken GetIDToken(TokenInfo token)
        {
            return TokenExtensions.DecodeAndVerifyLoginGovResponseToken(token, loginGovPubKey, loginGovKeyType);
        }

        public UserAttributes GetUserAttributesToken(HttpClient client, TokenInfo token)
        {
            return TokenExtensions.RetrieveLoginGovUserAttributesToken(token, userInfoEndpointURI, client);
        }

        public bool VerifyCodeAndState(string code, string state)
        {
            return !string.IsNullOrEmpty(code) && !string.IsNullOrEmpty(state);
        }

        public bool VerifyHttpStatusMessage(HttpResponseMessage httpMsg)
        {
            return httpMsg != null && httpMsg.StatusCode != HttpStatusCode.NotAcceptable;
        }
    }
}
