using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using BackendApi.Models;
using BackendApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Bson;
using MongoDB.Driver;

var builder = WebApplication.CreateBuilder(args);

// Services
builder.Services.AddControllers();
builder.Services.AddAWSLambdaHosting(LambdaEventSource.RestApi);

builder.Services.AddSingleton<MongoRepository>(_ => MongoRepository.FromEnvironment());
builder.Services.AddSingleton<JwtService>();

// CORS (allow all or restrict to frontend origin)
var allowedOrigin = builder.Configuration["FrontendOrigin"] ?? "*";
builder.Services.AddCors(options =>
{
    options.AddPolicy("default", policy =>
    {
        if (allowedOrigin == "*")
        {
            policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod();
        }
        else
        {
            policy.WithOrigins(allowedOrigin).AllowAnyHeader().AllowAnyMethod();
        }
    });
});

// AuthN/AuthZ (JWT)
var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? string.Empty;
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(string.IsNullOrWhiteSpace(jwtSecret) ? "missing-secret-will-throw" : jwtSecret));

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Artist", policy => policy.RequireClaim(ClaimTypes.Role, "artist"));
    options.AddPolicy("Voter", policy => policy.RequireClaim(ClaimTypes.Role, "voter"));
});

var app = builder.Build();

app.UseCors("default");
app.UseAuthentication();
app.UseAuthorization();

// Minimal API endpoints

// Root
app.MapGet("/", () => "API is running");

// DTOs
record SignupRequest(string Username, string Role, string Password);
record LoginRequest(string Username, string Password);
record CreateDrawingRequest(string Title, string ImageUrl);

// Helpers
static string ComputeSha256(string input)
{
    using var sha = SHA256.Create();
    var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
    return Convert.ToHexString(bytes);
}

// POST /signup
app.MapPost("/signup", async (MongoRepository repo, SignupRequest req, HttpContext ctx) =>
{
    var roleLower = (req.Role ?? string.Empty).Trim().ToLowerInvariant();
    if (roleLower != "artist" && roleLower != "voter")
    {
        return Results.BadRequest(new { error = "Role must be 'artist' or 'voter'" });
    }

    var users = repo.Database.GetCollection<User>("Users");
    var existing = await users.Find(u => u.Username == req.Username).FirstOrDefaultAsync();
    if (existing != null)
    {
        return Results.Conflict(new { error = "Username already exists" });
    }

    var newUser = new User
    {
        Username = req.Username.Trim(),
        Role = roleLower,
        PasswordHash = ComputeSha256(req.Password)
    };

    await users.InsertOneAsync(newUser);
    return Results.Created($"/users/{newUser.Id}", new { id = newUser.Id, newUser.Username, newUser.Role });
});

// POST /login
app.MapPost("/login", async (MongoRepository repo, JwtService jwt, LoginRequest req) =>
{
    var users = repo.Database.GetCollection<User>("Users");
    var user = await users.Find(u => u.Username == req.Username).FirstOrDefaultAsync();
    if (user == null)
    {
        return Results.Unauthorized();
    }

    var hashed = ComputeSha256(req.Password);
    if (!string.Equals(user.PasswordHash, hashed, StringComparison.OrdinalIgnoreCase))
    {
        return Results.Unauthorized();
    }

    var token = jwt.GenerateToken(user.Id ?? string.Empty, user.Username, user.Role);
    return Results.Ok(new { token });
});

// POST /drawings (artist only)
app.MapPost("/drawings", async (HttpContext http, MongoRepository repo, CreateDrawingRequest req) =>
{
    var userId = http.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? string.Empty;
    var role = http.User.FindFirstValue(ClaimTypes.Role) ?? string.Empty;
    if (string.IsNullOrEmpty(userId) || role != "artist")
    {
        return Results.Forbid();
    }

    var drawings = repo.Database.GetCollection<Drawing>("Drawings");
    var drawing = new Drawing
    {
        Title = req.Title,
        ImageUrl = req.ImageUrl,
        ArtistId = userId,
        Votes = 0,
        CreatedAt = DateTime.UtcNow
    };
    await drawings.InsertOneAsync(drawing);
    return Results.Created($"/drawings/{drawing.Id}", drawing);
}).RequireAuthorization("Artist");

// POST /drawings/{id}/vote (voter only)
app.MapPost("/drawings/{id}/vote", async (string id, HttpContext http, MongoRepository repo) =>
{
    var role = http.User.FindFirstValue(ClaimTypes.Role) ?? string.Empty;
    if (role != "voter")
    {
        return Results.Forbid();
    }

    if (!ObjectId.TryParse(id, out var objId))
    {
        return Results.BadRequest(new { error = "Invalid drawing id" });
    }

    var drawings = repo.Database.GetCollection<Drawing>("Drawings");
    var update = Builders<Drawing>.Update.Inc(d => d.Votes, 1);
    var result = await drawings.UpdateOneAsync(d => d.Id == objId.ToString(), update);
    if (result.MatchedCount == 0)
    {
        return Results.NotFound();
    }
    return Results.Ok(new { ok = true });
}).RequireAuthorization("Voter");

// GET /leaderboard?top=n
app.MapGet("/leaderboard", async (int? top, MongoRepository repo) =>
{
    var n = top.GetValueOrDefault(10);
    n = Math.Clamp(n, 1, 100);
    var drawings = repo.Database.GetCollection<Drawing>("Drawings");
    var list = await drawings
        .Find(FilterDefinition<Drawing>.Empty)
        .SortByDescending(d => d.Votes)
        .Limit(n)
        .ToListAsync();
    return Results.Ok(list);
});

app.Run();
