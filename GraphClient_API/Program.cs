var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen();

//builder.Services.AddAuthorization();
builder.Services.AddHttpClient(); // For calling API 2

builder.Services.AddControllers();
builder.Services.AddSwaggerGen();

// Add User Secrets
builder.Configuration.AddUserSecrets<Program>();

// Initialize the static class with configuration
TokenValidator.Initialize(builder.Configuration);

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
