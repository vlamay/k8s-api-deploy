var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers(); // Ensure controllers are registered

var app = builder.Build();

// Configure the HTTP request pipeline.
// No specific pipeline configuration needed for this simple service beyond controller mapping.

app.MapControllers(); // This enables attribute routing for controllers

app.Run();
