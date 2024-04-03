using Microsoft.EntityFrameworkCore;
using SecureCryptAPI.Middleware;

namespace SecureCryptAPI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();

            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
            builder.Services.AddDbContext<YourDbContext>(options => options.UseSqlServer(connectionString));

            builder.Services.AddDistributedMemoryCache();
            builder.Services.AddSession(options =>
            {
                options.Cookie.Name = ".YourApp.Session";
                options.IdleTimeout = TimeSpan.FromMinutes(30);
            });

            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseAuthorization();
            app.UseAuthentication();
            app.UseSession();


            app.MapControllers();

            app.UseMiddleware<APIKeyMiddleware>();

            app.Run();
        }
    }
}