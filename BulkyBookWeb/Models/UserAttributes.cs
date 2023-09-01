namespace BulkyBookWeb.Models
{
    public class UserAttributes
    {
        public string birthdate { get; set; }
        public string email { get; set; }
        public string email_verified { get; set; }
        public string[] all_emails { get; set; }
        public string family_name { get; set; }
        public string given_name { get; set; }
        public string iss { get; set; }
        public string phone { get; set; }
        public bool phone_verified { get; set; }
        public string social_security_number { get; set; }
        public string sub { get; set; }
        public Int64 verified_at { get; set; }
    }
}
