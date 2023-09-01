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
    }
}
