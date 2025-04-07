using JWT_withWebAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace JWT_withWebAPI.Data
{
    public class UserDbContext : DbContext
    {
        public UserDbContext(DbContextOptions<UserDbContext> options) : base(options)
        {
        }
        public DbSet<User> Users { get; set; }


    }
}
