using System.Text;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SecureApi.Models;
using SecureApi.Services;
using SecureApi.Repositories;
using BCrypt.Net;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// -------------------------------------------------------------
// SERVICES
// -------------------------------------------------------------
builder.Services.AddSingleton<JwtService>();
builder.Services.AddSingleton<SecurityMonitor>();
builder.Services.AddSingleton<RefreshStore>();
builder.Services.AddSingleton<LogService>();
builder.Services.AddSingleton<IUserRepository, UserRepository>();
builder.Services.AddSingleton<ISessionRepository, SessionRepository>();
builder.Services.AddSingleton<DocumentService>();

// -------------------------------------------------------------
// CORS
// -------------------------------------------------------------
builder.Services.AddCors(options =>
{
    options.AddPolicy("AivoCors", policy =>
    {
        policy.WithOrigins(
            "https://graceful-lamington-186ce2.netlify.app",
            "https://aivo-pwa.pages.dev/"
        )
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

// -------------------------------------------------------------
// AUTHORIZATION (admin / user)
// -------------------------------------------------------------
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("admin", policy => policy.RequireRole("admin"));
    options.AddPolicy("user", policy => policy.RequireRole("user"));
});

var app = builder.Build();

// -------------------------------------------------------------
// MIDDLEWARE
// -------------------------------------------------------------
app.UseRouting();
app.UseCors("AivoCors");
app.UseAuthentication();
app.UseAuthorization();

// -------------------------------------------------------------
// LOGIN
// -------------------------------------------------------------
app.MapPost("/auth/login", (
    LoginRequest request,
    HttpContext ctx,
    JwtService jwt,
    SecurityMonitor monitor,
    RefreshStore store,
    LogService log) =>
{
    var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var suspicious = monitor.RegisterIp(request.Username, ip);

    log.Write($"Login attempt by {request.Username} from {ip}");

    if (suspicious)
    {
        log.Write($"Suspicious IP detected for {request.Username}");
        store.FlagPasswordChange(request.Username);
    }

    if (request.Username == "admin" && request.Password == "admin")
    {
        var token = jwt.GenerateToken("admin", "admin");
        var refresh = jwt.GenerateRefreshToken();
        store.Save("admin", refresh);

        log.Write("Admin logged in");

        return Results.Ok(new LoginResponse(token, "admin", refresh));
    }

    if (request.Username == "user" && request.Password == "user")
    {
        var token = jwt.GenerateToken("user", "user");
        var refresh = jwt.GenerateRefreshToken();
        store.Save("user", refresh);

        log.Write("User logged in");

        return Results.Ok(new LoginResponse(token, "user", refresh));
    }

    log.Write($"Failed login for {request.Username}");
    return Results.Unauthorized();
});

// -------------------------------------------------------------
// REFRESH TOKEN
// -------------------------------------------------------------
app.MapPost("/auth/refresh", (
    RefreshRequest req,
    JwtService jwt,
    RefreshStore store,
    LogService log) =>
{
    if (!store.IsValid(req.Username, req.RefreshToken))
    {
        log.Write($"Invalid refresh token for {req.Username}");
        return Results.Unauthorized();
    }

    if (store.MustChangePassword(req.Username))
    {
        log.Write($"Password change required for {req.Username}");
        return Results.Json(new { error = "password_change_required" }, statusCode: 403);
    }

    var newToken = jwt.GenerateToken(req.Username, req.Role);
    var newRefresh = jwt.GenerateRefreshToken();

    store.Save(req.Username, newRefresh);

    log.Write($"Refresh token used by {req.Username}");

    return Results.Ok(new RefreshResponse(newToken, newRefresh));
});

// -------------------------------------------------------------
// ENDPOINT SÉCURISÉ (test)
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
    ISessionRepository sessionRepo,
    LogService log) =>
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

    log.Write($"Password changed for {request.Username}");

    return Results.Ok(new { success = true });
});

// -------------------------------------------------------------
// ADMIN — STATS
// -------------------------------------------------------------
app.MapGet("/admin/stats", () =>
{
    return Results.Ok(new {
        users = 2,
        sessions = 5,
        suspicious = 1
    });
})
.RequireAuthorization("admin");

// -------------------------------------------------------------
// ADMIN — USERS
// -------------------------------------------------------------
app.MapGet("/admin/users", () =>
{
    return Results.Ok(new[] {
        new { username = "admin", role = "admin" },
        new { username = "user", role = "user" }
    });
})
.RequireAuthorization("admin");

// -------------------------------------------------------------
// ADMIN — REVOKE ALL SESSIONS
// -------------------------------------------------------------
app.MapPost("/admin/revoke-all", (
    ISessionRepository repo,
    LogService log) =>
{
    repo.RevokeAllSessions();
    log.Write("Admin revoked all sessions");
    return Results.Ok(new { success = true });
})
.RequireAuthorization("admin");

// -------------------------------------------------------------
// ADMIN — LOGS
// -------------------------------------------------------------
app.MapGet("/admin/logs", () =>
{
    var lines = System.IO.File.Exists("Data/logs.txt")
        ? System.IO.File.ReadAllLines("Data/logs.txt")
        : Array.Empty<string>();

    var logs = lines.Select(line =>
    {
        var parts = line.Split(" | ");
        return new { timestamp = parts[0], message = parts[1] };
    });

    return Results.Ok(logs);
})
.RequireAuthorization("admin");

app.Run();

// -------------------------------------------------------------
// DOCUMENTS
//--------------------------------------------------------------
app.MapPost("/documents/upload", async (
    HttpContext ctx,
    DocumentService docs,
    LogService log) =>
{
    var user = ctx.User.Identity?.Name;
    if (user == null)
        return Results.Unauthorized();

    var file = ctx.Request.Form.Files.FirstOrDefault();
    if (file == null)
        return Results.BadRequest(new { error = "no_file"});
    
    var saved = docs.SaveFile(user, file);

    log.Write($"Document uploaded by {user}: {saved.FileName}");

    return Results.Ok(saved);
})
.RequireAuthorization();
// ---------------------------------------------------------------
// Liste des Documents utilisateur 
// ---------------------------------------------------------------
app.MapGet("/documents/list", (
    HttpContext ctx,
    DocumentService docs) =>
{
    var user = ctx.User.Identity?.Name;
    if (user == null)
        return Results.Unauthorized();

    var list = docs.GetAll().Where(d => d.Owner == user);
    return Results.Ok(list);
})
.RequireAuthorization();

// ----------------------------------------------------------------
// Supprimer un documents
// ----------------------------------------------------------------
app.MapDelete("/documents/delete/{id}", (
    string id,
    HttpContext ctx,
    DocumentService docs,
    LogService log) =>
{
    var user = ctx.User.Identity?.Name;
    if (user == null)
        return Results.Unauthorized();

    var all = docs.GetAll();
    var doc = all.FirstOrDefault(d => d.Id == id);

    if (doc == null)
        return Results.NotFound();

    if (doc.Owner != user)
        return Results.Forbid();

    docs.Delete(id);

    log.Write($"Document deleted by {user}: {doc.FileName}");

    return Results.Ok(new { success = true });
})
.RequireAuthorization();

// -------------------------------------------------------------------
// Télécharger un document
// -------------------------------------------------------------------
app.MapGet("/documents/download/{id}", (
    string id,
    HttpContext ctx,
    DocumentService docs) =>
{
    var user = ctx.User.Identity?.Name;
    if (user == null)
        return Results.Unauthorized();

    var all = docs.GetAll();
    var doc = all.FirstOrDefault(d => d.Id == id);

    if (doc == null)
        return Results.NotFound();

    if (doc.Owner != user)
        return Results.Forbid();

    var bytes = File.ReadAllBytes(doc.Path);
    return Results.File(bytes, "application/octet-stream", doc.FileName);
})
.RequireAuthorization();


// -------------------------------------------------------------
// RECORDS
// -------------------------------------------------------------
public record LoginRequest(string Username, string Password);
public record ChangePasswordRequest(string Username, string OldPassword, string NewPassword);
public record LoginResponse(string Token, string Role, string RefreshToken);
public record RefreshResponse(string Token, string RefreshToken);
public record RefreshRequest(string Username, string Role, string RefreshToken);
