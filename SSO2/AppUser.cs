namespace SSO2
{
    public class AppUser
    {
        public Guid Id { get; set; }
        public string Email { get; set; } 
        public string LoggedInUsing {  get; set; } 

        public ICollection<RefreshToken> RefreshTokens { get; set; }  = new List<RefreshToken>();  
        
    }
}
