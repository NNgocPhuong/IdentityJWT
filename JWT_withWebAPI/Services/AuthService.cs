using JWT_withWebAPI.Data;
using JWT_withWebAPI.Entities;
using JWT_withWebAPI.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT_withWebAPI.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserDbContext _userDbContext;
        private readonly IConfiguration _configuration;
        public AuthService(UserDbContext dbContext, IConfiguration configuration) 
        {
            _configuration = configuration;
            _userDbContext = dbContext;
        }
        public async Task<string?> LoginAsync(UserDto request)
        {
            var user = await _userDbContext.Users.FirstOrDefaultAsync(u => u.UserName == request.UserName);
            if (user is null)
            {
                return null;
            }
            
            if (new PasswordHasher<User>().VerifyHashedPassword(user, user.PasswordHash, request.Password)
                == PasswordVerificationResult.Failed)
            {
                return null;
            }
            
            return CreateToken(user);
        }

        public async Task<User?> RegisterAsync(UserDto request)
        {
            if (await _userDbContext.Users.AnyAsync(u => u.UserName == request.UserName)) {
                return null;
            }
            var user = new User();
            var hashPassword = new PasswordHasher<User>()
                .HashPassword(user, request.Password);
            user.UserName = request.UserName;
            user.PasswordHash = hashPassword;
            _userDbContext.Add(user);
            await _userDbContext.SaveChangesAsync();
            return user;
        }
        private string CreateToken(User user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration.GetValue<string>("AppSettings:Token")!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
            var tokenDescriptor = new JwtSecurityToken(
                issuer: _configuration.GetValue<string>("AppSettings:Issuer"),
                audience: _configuration.GetValue<string>("AppSettings:Audience"),
                claims: claims,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials: creds
                );
            return new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);
        }
    }
}
