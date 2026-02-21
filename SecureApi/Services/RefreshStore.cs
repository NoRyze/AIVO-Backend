namespace SecureApi.Services;

public class RefreshStore
{
    private readonly Dictionary<string, string> _refreshTokens = new();
    private readonly Dictionary<string, bool> _mustChangePassword = new();

    public void Save(string username, string refreshToken)
    {
        _refreshTokens[username] = refreshToken;
    }

    public bool IsValid(string username, string refreshToken)
    {
        return _refreshTokens.TryGetValue(username, out var stored) && stored == refreshToken;
    }

    public void FlagPasswordChange(string username)
    {
        _mustChangePassword[username] = true;
    }

    public bool MustChangePassword(string username)
    {
        return _mustChangePassword.TryGetValue(username, out var flag) && flag;
    }
}