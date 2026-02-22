public async Task UpdateUserAsync(User user)
{
    _users[user.Username] = user;
    await SaveAsync();
}