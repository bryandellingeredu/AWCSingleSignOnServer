using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Claims;

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

        public static JwtSecurityToken GenerateAccessToken(HttpContext context, string email, string loggedInUsing, int personId) 
        {
            var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
            var jwtSettingsConfig = configuration.GetSection("JWTSettings");
            var secretKey = jwtSettingsConfig["SecretKey"];
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            var claims = new List<Claim>
            {
              new Claim(JwtRegisteredClaimNames.Sub, email),
              new Claim(JwtRegisteredClaimNames.Email, email),
              new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
              new Claim("custom:loggedInUsing", loggedInUsing), // Custom claim
              new Claim("custom:personId", personId.ToString()) // Custom claim
            };

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var issuer = $"{context.Request.Scheme}://{context.Request.Host}/SingleSignOn";
            var audience = "resource-server-1";

            var jwtToken = new JwtSecurityToken(
             issuer: issuer,
             audience: audience,
             claims: claims,
             expires: DateTime.UtcNow.AddMinutes(60), // Short-lived access token
             signingCredentials: creds
             );

            return jwtToken;    
        }
    }
}
