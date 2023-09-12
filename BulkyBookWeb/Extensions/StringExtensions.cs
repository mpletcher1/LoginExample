using Microsoft.CodeAnalysis;
using System.Text;
using System.Web;

namespace BulkyBookWeb.Extensions
{
    public class StringExtensions
    {
        public static string GetRandomString(int len)
        {
            var r = new Random();
            var str = new String(Enumerable.Range(0, len).Select(n => (Char)(r.Next(32, 127))).ToArray());
            return str;
        }
        public static string GetUrlParameter(HttpRequest request, string paramName)
        {
            string result = "";
            var urlParams = HttpUtility.ParseQueryString(request.QueryString.ToString());
            if (urlParams.AllKeys.Contains(paramName))
            {
                result = urlParams.Get(paramName);
            }
            return result;
        }

        public static string GenerateParametrizedURLEntry(string paramName, string paramValue, bool lastStr = false)
        {
            string result = lastStr == true ? "" : "&";
            return paramName + "=" + paramValue + result;
        }

    }
}
