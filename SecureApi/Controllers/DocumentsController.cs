using System.Reflection.Metadata;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecureApi.Services;

namespace SecureApi.Controllers;

[ApiController]
[Route("[controller]")]
public class DocumentsController : ControllerBase
{
    private readonly DocumentService _service;

    public DocumentsController(DocumentService service)
    {
        _service = service;
    }

    // GET /documents
    [Authorize]
    [HttpGet]
    public IActionResult GetAll()
    {
        var docs = _service.GetAll();
        return Ok(docs);
    }

    // POST /documents (ADMIN ONLY)
    [Authorize(Roles = "admin")]
    [HttpPost]
    public IActionResult Upload([FromForm] IFormFile file)
    {
        if (file == null)
            return BadRequest("Aucun fichier reçu.");

        var username = User.Identity?.Name ?? "unknown"; 
        var doc = _service.SaverFile(username, file);

        return Ok(doc);
    }

    // DELETE /documents/{id} (ADMIN ONLY)
    [Authorize(Roles = "admin")]
    [HttpDelete("{id}")]
    public IActionResult Delete(string id)
    {
        var ok = _service.Delete(id);
        if (!ok)
            return NotFound();

        return Ok();
    }
}