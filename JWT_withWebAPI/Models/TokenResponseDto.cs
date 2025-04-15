using Microsoft.EntityFrameworkCore.Migrations.Operations;

namespace JWT_withWebAPI.Models
{
    public class TokenResponseDto
    {
        public required string AccessToken { get; set; }
        public required string RefreshToken { get; set; }
    }
}
