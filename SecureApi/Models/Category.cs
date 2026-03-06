namespace SecureApi.Models
{
    public class SubDocument
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Label { get; set; } = "";
        public string? FileName { get; set; }
        public string? FilePath { get; set; }
    }

    public class Category
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string Name { get; set; } = "";
        public int Order { get; set; }
        public List<SubDocument> SubDocuments { get; set; } = new();
    }
}