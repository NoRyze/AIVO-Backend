namespace SecureApi.Models;

public record RefreshResponse
{
    public required string Token { get; set; }
}