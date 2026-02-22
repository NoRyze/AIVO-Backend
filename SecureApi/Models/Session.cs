namespace SecureApi.Models;

public class Session
{
    public string SessionId { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public bool IsRevoked { get; set; } = false;
}