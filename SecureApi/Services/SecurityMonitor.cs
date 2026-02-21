namespace SecureApi.Services;

public class SecurityMonitor
{
    private readonly Dictionary<string, List<DateTime>> _ipChanges = new();
    private readonly Dictionary<string, string> _lastIp = new();
    private readonly TimeSpan _window = TimeSpan.FromMinutes(5);

    // Retourne true si 2 changements d’IP en moins de 5 minutes
    public bool RegisterIp(string username, string ip)
    {
        if (!_lastIp.TryGetValue(username, out var oldIp))
        {
            _lastIp[username] = ip;
            return false;
        }

        if (oldIp == ip)
            return false;

        _lastIp[username] = ip;

        if (!_ipChanges.ContainsKey(username))
            _ipChanges[username] = new List<DateTime>();

        _ipChanges[username].Add(DateTime.UtcNow);

        _ipChanges[username] = _ipChanges[username]
            .Where(t => DateTime.UtcNow - t < _window)
            .ToList();

        return _ipChanges[username].Count >= 2;
    }
}