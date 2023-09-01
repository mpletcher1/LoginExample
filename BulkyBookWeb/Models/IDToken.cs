namespace BulkyBookWeb.Models
{
    public class IDToken
    {
        public string sub { get; set; }
        public string iss { get; set; }
        public string acr { get; set; }
        public string nonce { get; set; }
        public string aud { get; set; }
        public string jti { get; set; }
        public string at_hash { get; set; }
        public string c_hash { get; set; }
        public Int64 exp { get; set; }
        public Int64 iat { get; set; }
        public Int64 nbf { get; set; }
    }
}
