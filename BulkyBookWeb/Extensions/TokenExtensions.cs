using BulkyBookWeb.Models;

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
    }
}
