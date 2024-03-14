using Microsoft.IdentityModel.Tokens;
using SecurityNowApi.Interfaces;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace SecurityNowApi.Services
{
    public class TokenService : ITokenService
    {
        // Generate access token
        public JwtSecurityToken GenerateAccessToken(IEnumerable<Claim> claims, IConfiguration _config)
        {
            var key = _config.GetSection("JWT").GetValue<string>("SecretKey") ??
                throw new InvalidOperationException("JWT Secret is missing in appsettings.json");

            var privateKey = Encoding.UTF8.GetBytes(key);

            var signingCredentials = new SigningCredentials(new SymmetricSecurityKey(privateKey),
                SecurityAlgorithms.HmacSha256Signature);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(_config.GetSection("JWT")
                                    .GetValue<double>("AccessExpiration")),
                Audience = _config.GetSection("JWT")
                        .GetValue<string>("ValidAudience"),
                Issuer = _config.GetSection("JWT").GetValue<string>("ValidIssuer"),
                SigningCredentials = signingCredentials
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
            return token;
        }

        // Generate refresh token
        public string GenerateRefreshToken()
        {
            var secureRandomBytes = new byte[128];
            using var randomNumberGenerator = RandomNumberGenerator.Create();
            randomNumberGenerator.GetBytes(secureRandomBytes);
            var refreshToken = Convert.ToBase64String(secureRandomBytes);
            return refreshToken;
        }

        // Get principal from expired token
        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token, IConfiguration _config)
        {
            var secretKey = _config["JWT:SecretKey"] ??
                throw new InvalidOperationException("JWT Secret is missing in appsettings.json");

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(
                    SecurityAlgorithms.HmacSha256,
                    StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }
            return principal;
        }
    }
}
