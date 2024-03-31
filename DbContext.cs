using Microsoft.EntityFrameworkCore;
using System;
namespace SecureCryptAPI
{
    public class YourDbContext : DbContext
    {
        public YourDbContext(DbContextOptions<YourDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
    }

    public class User
    {
        public int Id { get; set; }
        public string? Email { get; set; }
        public string? ApiKey { get; set; }
    }
}
