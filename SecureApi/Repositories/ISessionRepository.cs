using SecureApi.Models;

namespace SecureApi.Repositories;

public interface ISessionRepository
{
    Task<Session?> GetSessionAsync(string sessionId);
    Task SaveSessionAsync(Session session);
    Task RevokeSessionAsync(string sessionId);
    Task RevokeAllSessionsAsync(string username);
    Task<IEnumerable<Session>> GetSessionsForUserAsync(string username);

    // Méthode globale pour l'admin
    void RevokeAllSessions();
}