using System.Buffers;
using System.IO.Enumeration;
using System.Linq.Expressions;
using System.Text.Json;

namespace SecureApi.Services;

public class DocumentService
{
    private readonly string _folder = "Data/Documents";
    private readonly string _indexFile = "Data/documents.json";

    public DocumentService()
    {
        if (!Directory.Exists(_folder))
             Directory.CreateDirectory(_folder);

        if (!File.Exists(_indexFile))
             File.WriteAllText(_indexFile, "[]");
    }

    public List<DocumentInfo> GetAll()
    {
        var json = File.ReadAllText(_indexFile);
        return JsonSerializer.Deserialize<List<DocumentInfo>>(json) ?? new();
    }

    public void SaveIndex(List<DocumentInfo> docs)
    {
        var json = JsonSerializer.Serialize(docs, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_indexFile, json);
    }

    public DocumentInfo SaveFile(string username, IFormFile file)
    {
        var id = Guid.NewGuid().ToString();
        var filePath = Path.Combine(_folder, id + "_" + file.FileName);

        using (var stream = new FileStream(filePath, FileMode.Create))
        {
            file.CopyTo(stream);
        }

        var doc = new DocumentInfo
        {
            Id = id, 
            FileName = file.Name,
            Owner = filePath,
            UploadedAt = DateTime.Now
        };

        var docs = GetAll();
        docs.Add(doc);
        SaveIndex(docs);

        return doc;
    }

    public bool Delete(string id)
    {
        var docs = GetAll();
        var doc = docs.FirstOrDefault(d => d.Id == id);

        if (doc == null)
            return false;

        if (File.Exists(doc.Path))
            File.Delete(doc.Path);

        docs.Remove(doc);
        SaveIndex(docs);

        return true;
    }
}

public class DocumentInfo
{
    public string Id { get; set; }
    public string FileName { get; set; }
    public string Owner { get; set; }
    public string Path { get; set; }
    public DateTime UploadedAt { get; set; }
}