using Microsoft.AspNetCore.Mvc;

namespace CSharpService.Controllers;

[ApiController]
[Route("[controller]")]
public class VersionController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        return Ok(new { service = "C#", version = "1.0.0", dotnetVersion = System.Environment.Version.ToString() });
    }
}
