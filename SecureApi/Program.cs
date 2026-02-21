var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapPost("/auth/login", (LoginRequest request) =>
{
    if (request.Username == "admin" && request.Password == "admin")
    {
        return Results.Ok(new LoginResponse
        {
            Token = "admin-token-123",
            Role = "admin"
        });
    }

    if (request.Username == "user" && request.Password == "user")
    {
        return Results.Ok(new LoginResponse
        {
            Token = "user-token-123",
            Role = "user"
        });
    }

    return Results.Unauthorized();
});

app.Run();

record LoginRequest(string Username, string Password);

record LoginResponse
{
    public required string Token { get; set; }
    public required string Role { get; set; }
}