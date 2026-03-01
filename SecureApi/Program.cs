using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SecureApi.Models;
using SecureApi.Services;
using SecureApi.Repositories;
using BCrypt.Net;

var builder = WebApplication.CreateBuilder(args);

// -------------------------------------------------------------
// SERVICES
// -------------------------------------------------------------
builder.Services.AddSingleton<JwtService>();
builder.Services.AddSingleton<SecurityMonitor>();
builder.Services.AddSingleton<RefreshStore>();
builder.Services.AddSingleton<IUserRepository, UserRepository>();
builder.Services.AddSingleton<ISessionRepository, SessionRepository>();

// -------------------------------------------------------------
// CORS
// -------------------------------------------------------------
builder.Services.AddCors(options =>
{
    options.AddPolicy("AivoCors", policy =>
    {
        policy.WithOrigins("https://graceful-lamington-186ce2.netlify.app")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

// -------------------------------------------------------------
// AUTHENTICATION JWT
// -------------------------------------------------------------
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

// -------------------------------------------------------------
// MIDDLEWARE
// -------------------------------------------------------------
app.UseRouting();              // ← CRITIQUE : permet à OPTIONS de fonctionner
app.UseCors("AivoCors");       // ← AVANT Auth
app.UseAuthentication();
app.UseAuthorization();

// -------------------------------------------------------------
// LOGIN
// -------------------------------------------------------------
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

// -------------------------------------------------------------
// REFRESH TOKEN
// -------------------------------------------------------------
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

// -------------------------------------------------------------
// ENDPOINT SÉCURISÉ
// -------------------------------------------------------------
app.MapGet("/secure/data", (ClaimsPrincipal user) =>
{
    var username = user.Identity?.Name ?? "unknown";
    return Results.Ok(new { message = $"Données secrètes AIVO pour {username}" });
})
.RequireAuthorization();

// -------------------------------------------------------------
// CHANGE PASSWORD
// -------------------------------------------------------------
app.MapPost("/auth/change-password", async (
    ChangePasswordRequest request,
    IUserRepository userRepo,
    ISessionRepository sessionRepo) =>
{
    var user = await userRepo.GetUserAsync(request.Username);

    if (user == null)
        return Results.BadRequest(new { error = "user_not_found" });

    if (!BCrypt.Net.BCrypt.Verify(request.OldPassword, user.PasswordHash))
        return Results.BadRequest(new { error = "invalid_old_password" });

    user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);
    user.PasswordChangeRequired = false;

    await userRepo.UpdateUserAsync(user);
    await sessionRepo.RevokeAllSessionsAsync(user.Username);

    return Results.Ok(new { success = true });
});

app.Run();

// -------------------------------------------------------------
// RECORDS
// -------------------------------------------------------------
public record LoginRequest(string Username, string Password);
public record ChangePasswordRequest(string Username, string OldPassword, string NewPassword);