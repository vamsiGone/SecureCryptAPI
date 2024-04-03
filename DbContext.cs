using Microsoft.EntityFrameworkCore;
using System;
using System.ComponentModel.DataAnnotations;

namespace SecureCryptAPI
{
    public class YourDbContext : DbContext
    {
        public YourDbContext(DbContextOptions<YourDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
        public DbSet<EncryptDecryptLog> EncryptDecryptLog { get; set; }

    }

    public class User
    {
        public int Id { get; set; }
        public string? Email { get; set; }
        public string? ApiKey { get; set; }

        public int Userid { get; set; }
    }

    public class EncryptDecryptLog
    {
        [Key]
        public int Id { get; set; }

        public string? PlainText { get; set; }

        public string? EncryptRDecryptText { get; set; }

        public string? privatekey { get; set; }

        public string? Mode { get; set; }

        public int UserId { get; set; }
    }

    public class HistoryEntry
    {
        public int Sno { get; set; }
        public int Id { get; set; }
        public string? PlainText { get; set; }
        public string? EncryptRDecryptText { get; set; }
        public string? privatekey { get; set; }
        public string? Mode { get; set; }
        public int UserId { get; set; }
    }
}
