namespace SecureApi.Models;

public record LoginResponse
{
    public required string Token { get; set; }
    public required string Role { get; set; }
    public required string RefreshToken { get; set; }
}