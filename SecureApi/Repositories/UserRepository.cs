using System.Text.Json;
using SecureApi.Models;

namespace SecureApi.Repositories;

public class UserRepository : IUserRepository
{
    private readonly string _filePath = "Data/users.json";
    private Dictionary<string, User> _users = new();

    public UserRepository()
    {
        if (File.Exists(_filePath))
        {
            var json = File.ReadAllText(_filePath);
            _users = JsonSerializer.Deserialize<Dictionary<string, User>>(json)
                     ?? new Dictionary<string, User>();
        }
    }

    public Task<User?> GetUserAsync(string username)
    {
        _users.TryGetValue(username, out var user);
        return Task.FromResult(user);
    }

    public Task UpdateUserAsync(User user)
    {
        _users[user.Username] = user;
        return SaveAsync();
    }

    public Task SaveAsync()
    {
        var json = JsonSerializer.Serialize(_users, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        File.WriteAllText(_filePath, json);
        return Task.CompletedTask;
    }
}