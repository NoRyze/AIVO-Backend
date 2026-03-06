using SecureApi.Models;

namespace SecureApi.Services
{
    public class CategoryService
    {
        private readonly List<Category> _categories = new();

        public CategoryService()
        {
            Seed();
        }

        private void Seed()
        {
            // VHM RANG
            var vhmRang = new Category { Name = "VHM RANG", Order = 0 };
            vhmRang.SubDocuments.AddRange(CreateStandardVhmSubdocs());
            _categories.Add(vhmRang);

            // VHM PC
            var vhmPc = new Category { Name = "VHM PC", Order = 1 };
            vhmPc.SubDocuments.AddRange(CreateStandardVhmSubdocs());
            _categories.Add(vhmPc);

            // VHM LOG
            var vhmLog = new Category { Name = "VHM LOG", Order = 2 };
            vhmLog.SubDocuments.AddRange(CreateStandardVhmSubdocs());
            _categories.Add(vhmLog);

            // Description des kits
            var descKits = new Category { Name = "Description des kits", Order = 3 };
            descKits.SubDocuments.AddRange(CreateDescriptionKitsSubdocs());
            _categories.Add(descKits);

            // Recherche de panne (vide au départ)
            var recherche = new Category { Name = "Recherche de panne", Order = 4 };
            _categories.Add(recherche);
        }

        private IEnumerable<SubDocument> CreateStandardVhmSubdocs()
        {
            yield return new SubDocument { Label = "Guide technique" };
            yield return new SubDocument { Label = "Manuel de maintenance" };
            yield return new SubDocument { Label = "Catalogue illustré" };
            yield return new SubDocument { Label = "Schéma" };
            yield return new SubDocument { Label = "Alisson BVA" };
        }

        private IEnumerable<SubDocument> CreateDescriptionKitsSubdocs()
        {
            string[] labels =
            {
                "Fiche montage STC B2M VHM RANG",
                "Fiche montage CMT sur VHM PC",
                "Fiche montage CMT sur VHM LOG",
                "Fiche montage Coupe-câbles",
                "Fiche montage Protection contre les mines (montage véhicule dissocié)",
                "Fiche montage Protection contre les mines (montage véhicule complet)",
                "Fiche montage Tourelleau téléopéré (TOP)",
                "Fiche montage Kit génie",
                "Fiche dépose Kit génie",
                "Fiche montage Grille de protection anti-roquettes",
                "Manuel d'installation et dépose Système de brouillage sur VHM LOG",
                "Manuel d'installation et dépose Système brouillage sur VHM RANG/PC",
                "Fiche montage Marchepied",
                "Notice de montage Kit AT4CS VHM RANG",
                "Notice de montage Kit ERYX VHM RANG",
                "Notice de montage Kit MILAN VHM RANG",
                "Notice montage Kit Mortier 81mm VHM RANG",
                "Notice de montage Kit Mortier 120mm VHM LOG",
                "Notice de montage Kit Tireur d'élite VHM RANG",
                "Notice système interphone",
                "Notice de montage Protections des vitrages"
            };

            foreach (var l in labels)
                yield return new SubDocument { Label = l };
        }

        public IEnumerable<Category> GetAll() => _categories.OrderBy(c => c.Order);

        public Category? GetCategory(string id) => _categories.FirstOrDefault(c => c.Id == id);

        public SubDocument? GetSubDoc(string id) =>
            _categories.SelectMany(c => c.SubDocuments).FirstOrDefault(s => s.Id == id);

        public Category Create(string name)
        {
            var cat = new Category { Name = name, Order = _categories.Count };
            _categories.Add(cat);
            return cat;
        }

        public void RenameCategory(string id, string newName)
        {
            var cat = GetCategory(id);
            if (cat != null) cat.Name = newName;
        }

        public void DeleteCategory(string id)
        {
            _categories.RemoveAll(c => c.Id == id);
        }

        public SubDocument? AddSubDoc(string categoryId, string label)
        {
            var cat = GetCategory(categoryId);
            if (cat == null) return null;
            var sub = new SubDocument { Label = label };
            cat.SubDocuments.Add(sub);
            return sub;
        }

        public void RenameSubDoc(string id, string newLabel)
        {
            var sub = GetSubDoc(id);
            if (sub != null) sub.Label = newLabel;
        }

        public void DeleteSubDoc(string id)
        {
            foreach (var c in _categories)
                c.SubDocuments.RemoveAll(s => s.Id == id);
        }
    }
}