namespace SecureApi.Services;

public class LogService
{
    private readonly string _filePath = "Data/logs.txt";

    public void Write(string message)
    {
        var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} | {message}";
        File.AppendAllLines(_filePath, new[] { line });
    }
}