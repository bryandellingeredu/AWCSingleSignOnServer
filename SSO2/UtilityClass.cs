using System.Security.Cryptography;

namespace SSO2
{
    public static class UtilityClass
    {
        public static RefreshToken GenerateRefreshToken()
        {
            var randomNumber = new Byte[32];
            using var rng = RandomNumberGenerator.Create(); 
            rng.GetBytes(randomNumber);
            return new RefreshToken { Token = Convert.ToBase64String(randomNumber) };
        }
    }
}
