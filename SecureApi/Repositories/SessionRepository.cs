using System.Text.Json;
using SecureApi.Models;

namespace SecureApi.Repositories;

public class SessionRepository : ISessionRepository
{
    private readonly string _filePath = "Data/sessions.json";
    private Dictionary<string, Session> _sessions = new();

    public SessionRepository()
    {
        if (File.Exists(_filePath))
        {
            var json = File.ReadAllText(_filePath);
            _sessions = JsonSerializer.Deserialize<Dictionary<string, Session>>(json)
                        ?? new Dictionary<string, Session>();
        }
    }

    public Task<Session?> GetSessionAsync(string sessionId)
    {
        _sessions.TryGetValue(sessionId, out var session);
        return Task.FromResult(session);
    }

    public Task SaveSessionAsync(Session session)
    {
        _sessions[session.SessionId] = session;
        return SaveAsync();
    }

    public Task RevokeSessionAsync(string sessionId)
    {
        if (_sessions.TryGetValue(sessionId, out var session))
        {
            session.IsRevoked = true;
        }

        return SaveAsync();
    }

    public Task RevokeAllSessionsAsync(string username)
    {
        foreach (var session in _sessions.Values.Where(s => s.Username == username))
        {
            session.IsRevoked = true;
        }

        return SaveAsync();
    }

    public Task<IEnumerable<Session>> GetSessionsForUserAsync(string username)
    {
        var result = _sessions.Values.Where(s => s.Username == username);
        return Task.FromResult(result);
    }

    private Task SaveAsync()
    {
        var json = JsonSerializer.Serialize(_sessions, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        File.WriteAllText(_filePath, json);
        return Task.CompletedTask;
    }
}