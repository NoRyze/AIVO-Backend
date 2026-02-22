public async Task RevokeAllSessionsAsync(string username)
{
    foreach (var session in _sessions.Values.Where(string => string.Username == username))
        session.IsRevoked = true;

    await SaveAsync();
}