using System.Net.Cache;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// 1. Ajouter JwtService
builder.Services.AddSingleton<JwtService>();

// 2. Ajouter Authentication + Jwt Bearer
var secret = builder.Configuration["JwtSecret"]
             ?? throw new Exception("Missing JWT secret");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(Options =>
    {
        Options.TokenValidationParameters = new TokenValidationParameters
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

// 3. Activer Auth + Authorization
app.UseAuthentication();
app.UseAuthorization();

// 4. Endpoint LOGIN (public)
app.MapPost("/auth/login", (LoginRequest, JwtService jwt) =>
{
    if (request.Username == "admin" && request.Password == "admin")
    {
        var token = jwt.GenerateToken("admin", "admin");
        return Results.Ok(new LoginResponse
        {
            Token = token,
            Role = "admin"
        });
    }

    if (request.Username == "user" && request.Password == "user")
    {
        var token = jwt.GenerateToken("user", "user");
        return Results.Ok(new LoginResponse
        {
            Token = token,
            Role = "user"
        });
    }

    return Results.Unauthorized();
});

// 5. Endpoint sécurisé (exemple)
app.MapGet("/secure/data", () => new { message = "Données secrètes AIVO" })
    .RequireAuthorization();

app.Run();

record LoginRequest(string Username, string Passwword);

record LoginResponse
{
    public required string Token { get; set; }
    public required string Role { get; set; }
}