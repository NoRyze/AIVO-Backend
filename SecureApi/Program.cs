using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SecureApi.Models;
using SecureApi.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<JwtService>();
builder.Services.AddSingleton<SecurityMonitor>();
builder.Services.AddSingleton<RefreshStore>();

var secret = builder.Configuration["JwtSecret"]
             ?? throw new Exception("Missing JWT secret");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret)),
            ValidateLifetime = true
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// LOGIN
app.MapPost("/auth/login", (LoginRequest request,
                            HttpContext ctx,
                            JwtService jwt,
                            SecurityMonitor monitor,
                            RefreshStore store) =>
{
    var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var suspicious = monitor.RegisterIp(request.Username, ip);

    if (suspicious)
    {
        Console.WriteLine($"[AIVO-SEC] IP suspecte pour {request.Username} (double changement < 5min)");
        store.FlagPasswordChange(request.Username);
    }

    if (request.Username == "admin" && request.Password == "admin")
    {
        var token = jwt.GenerateToken("admin", "admin");
        var refresh = jwt.GenerateRefreshToken();

        store.Save("admin", refresh);

        return Results.Ok(new LoginResponse
        {
            Token = token,
            Role = "admin",
            RefreshToken = refresh
        });
    }

    if (request.Username == "user" && request.Password == "user")
    {
        var token = jwt.GenerateToken("user", "user");
        var refresh = jwt.GenerateRefreshToken();

        store.Save("user", refresh);

        return Results.Ok(new LoginResponse
        {
            Token = token,
            Role = "user",
            RefreshToken = refresh
        });
    }

    return Results.Unauthorized();
});

// REFRESH
app.MapPost("/auth/refresh", (RefreshRequest req,
                              JwtService jwt,
                              RefreshStore store) =>
{
    if (!store.IsValid(req.Username, req.RefreshToken))
        return Results.Unauthorized();

    if (store.MustChangePassword(req.Username))
    {
        return Results.Json(new { error = "password_change_required" }, statusCode: 403);
    }

    var newToken = jwt.GenerateToken(req.Username, req.Role);
    var newRefresh = jwt.GenerateRefreshToken();

    store.Save(req.Username, newRefresh);

    return Results.Ok(new RefreshResponse
    {
        Token = newToken,
        RefreshToken = newRefresh
    });
});

// Endpoint sécurisé
app.MapGet("/secure/data", (ClaimsPrincipal user) =>
{
    var username = user.Identity?.Name ?? "unknown";
    return Results.Ok(new { message = $"Données secrètes AIVO pour {username}" });
})
.RequireAuthorization();

app.Run();

public record LoginRequest(string Username, string Password);