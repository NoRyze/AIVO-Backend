namespace SecureApi.Models;

public record RefreshRequest
{
    public required string Username { get; set; }
    public required string Role { get; set; }
    public required string RefreshToken { get; set; }
}