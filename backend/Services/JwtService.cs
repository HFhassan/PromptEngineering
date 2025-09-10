using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace BackendApi.Services
{
    public class JwtService
    {
        private readonly string _jwtSecret;

        public JwtService(string? secret = null)
        {
            _jwtSecret = secret ?? Environment.GetEnvironmentVariable("JWT_SECRET") ?? string.Empty;

            if (string.IsNullOrWhiteSpace(_jwtSecret))
            {
                throw new InvalidOperationException("JWT secret not provided. Set JWT_SECRET environment variable.");
            }
        }

        public string GenerateToken(string userId, string userName, string role)
        {
            var keyBytes = Encoding.UTF8.GetBytes(_jwtSecret);
            var securityKey = new SymmetricSecurityKey(keyBytes);
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Name, userName),
                new Claim(ClaimTypes.Role, role)
            };

            var token = new JwtSecurityToken(
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddDays(7),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}


