using System;
using System.Web;
using System.Collections.Specialized;
using Microsoft.AspNetCore.Hosting.Server;

namespace BulkyBookWeb.Security
{
    
    public class SecurityModule : IHttpModule
    {
        public SecurityModule() { }

        public string ModuleName
        {
            get { return typeof(IHttpModule).Name; }
        }

        public void Init(IHttpApplication application)
        {
            application.BeginRequest += EventHandler(Application_BeginRequest);
        }

        private void Application_BeginRequest(object source, EventArgs e)
        {
            var app = (IHttpApplication)source;
            var context = app.Context;
            var response = context.Response;

            ApplyClickjackingMeasure(response.Headers);
        }

        private void ApplyClickjackingMeasure(NameValueCollection headers)
        {
            const string securityPolicyHeader = "Content-Security-Policy";
            headers.Remove(securityPolicyHeader);
            headers.Add(securityPolicyHeader, "frame-ancestors 'none'");
        }

        public void Dispose { }
    }
    
}
