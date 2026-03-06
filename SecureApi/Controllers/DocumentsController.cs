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

    [Authorize]
    [HttpGet]
    public IActionResult GetAll()
    {
        return Ok(_service.GetAll());
    }

    [Authorize(Roles = "admin")]
    [HttpPost]
    public IActionResult Upload([FromForm] IFormFile file)
    {
        if (file == null)
            return BadRequest("Aucun fichier reçu.");

        var username = User.Identity?.Name ?? "unknown";
        var doc = _service.SaveFile(username, file);

        return Ok(doc);
    }

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