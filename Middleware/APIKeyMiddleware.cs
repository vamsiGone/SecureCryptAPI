using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace SecureCryptAPI.Middleware
{
    public class APIKeyMiddleware
    {
        private readonly RequestDelegate _next;
        private const string APIKEY = "ApiKey";
        private const string EMAIL = "Email";

        public APIKeyMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext httpContext)
        {
            if (!httpContext.Request.Headers.TryGetValue(APIKEY, out var extractedApiKey) || !httpContext.Request.Headers.TryGetValue(EMAIL, out var extractedEmail))
            {
                httpContext.Response.StatusCode = 401;
                await httpContext.Response.WriteAsync("Email or API Key missing");
                return;
            }

            var apiKey = extractedApiKey.ToString(); 
            var email = extractedEmail.ToString();
            httpContext.Session.SetString("Email",email);

            var serviceProvider = httpContext.RequestServices;
            using (var scope = serviceProvider.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<YourDbContext>();

                var user = await dbContext.Users.FirstOrDefaultAsync(u => u.Email == email && u.ApiKey == apiKey);

                if (user == null)
                {
                    httpContext.Response.StatusCode = 401;
                    await httpContext.Response.WriteAsync("Wrong Email or API Key: Unauthorized access");
                    return;
                }

                await _next(httpContext);
            }

        }
    }
}
