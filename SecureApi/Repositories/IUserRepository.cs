using SecureApi.Models;

namespace SecureApi.Repositories;

public interface IUserRepository
{
    Task<User?> GetUserAsync(string username);
    Task UpdateUserAsync(User user);
    Task SaveAsync();
}