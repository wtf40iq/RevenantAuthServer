using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RevenantAuthServer.Data;
using RevenantAuthServer.Models;
using RevenantAuthServer.Services;

// Render free: исчерпан лимит inotify — отключаем слежку за конфиг-файлами ДО создания builder'а
Environment.SetEnvironmentVariable("DOTNET_hostBuilder__reloadConfigOnChange", "false");
Environment.SetEnvironmentVariable("DOTNET_USE_POLLING_FILE_WATCHER", "1");

var builder = WebApplication.CreateBuilder(args);

// ===== Конфигурация =====
// Секрет JWT берётся из переменной окружения JWT_SECRET (обязательно задать на Render!).
// Дефолт — только для локальной разработки.
var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET")
    ?? builder.Configuration["Jwt:Secret"];

if (string.IsNullOrWhiteSpace(jwtSecret) || Encoding.UTF8.GetByteCount(jwtSecret) < 32)
{
    Console.WriteLine("[Auth] WARNING: JWT_SECRET не задан или короче 32 символов — использую dev-секрет. НЕ ДЛЯ ПРОДАКШЕНА!");
    jwtSecret = "revenant-DEV-secret-do-not-use-in-production-0123456789";
}

const string jwtIssuer = "revenant-auth-server";
const string jwtAudience = "revenant-launcher";

var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? "Data Source=data/revenant.db";

builder.Services.AddDbContext<AuthDbContext>(options => options.UseSqlite(connectionString));
builder.Services.AddSingleton(new TokenService(jwtSecret, jwtIssuer, jwtAudience));

builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
    policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

// Защита от brute-force: максимум 20 запросов в минуту с одного IP на auth-эндпоинты
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = async (context, ct) =>
    {
        context.HttpContext.Response.ContentType = "application/json";
        await context.HttpContext.Response.WriteAsync("{\"message\":\"Слишком много попыток. Подожди минуту.\"}", ct);
    };
    options.AddPolicy<string>("auth", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            Window = TimeSpan.FromMinutes(1),
            PermitLimit = 20,
            QueueLimit = 0
        }));
});

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret)),
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(30)
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// ===== База данных =====
Directory.CreateDirectory("data");
using (var scope = app.Services.CreateScope())
{
    scope.ServiceProvider.GetRequiredService<AuthDbContext>().Database.EnsureCreated();
}
Console.WriteLine("[Auth] Database ready");

app.UseCors();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// ===== Эндпоинты =====

app.MapGet("/", () => Results.Ok(new { name = "Revenant Auth Server", status = "ok" }));
app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

var auth = app.MapGroup("/api/auth").RequireRateLimiting("auth");

// Регистрация
auth.MapPost("/register", async (RegisterRequest req, AuthDbContext db, TokenService tokens) =>
{
    var error = ValidateCredentials(req.Username, req.Password);
    if (error != null)
        return Results.BadRequest(new { message = error });

    var username = req.Username!.Trim();

    if (await db.Users.AnyAsync(u => u.Username == username))
        return Results.Conflict(new { message = "Этот никнейм уже занят" });

    var (hash, salt) = PasswordHasher.Hash(req.Password!);

    var user = new User
    {
        Username = username,
        PasswordHash = hash,
        PasswordSalt = salt,
        RefreshToken = TokenService.CreateRefreshToken(),
        RefreshTokenExpiry = DateTime.UtcNow.Add(TokenService.RefreshTokenLifetime),
        LastLoginAt = DateTime.UtcNow
    };

    db.Users.Add(user);
    await db.SaveChangesAsync();

    Console.WriteLine($"[Auth] Registered: {username} (id={user.Id})");
    return Results.Ok(new AuthResponse(tokens.CreateAccessToken(user), user.RefreshToken!, user.Id, user.Username));
});

// Вход
auth.MapPost("/login", async (LoginRequest req, AuthDbContext db, TokenService tokens) =>
{
    if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { message = "Введи никнейм и пароль" });

    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == req.Username.Trim());

    if (user == null || !PasswordHasher.Verify(req.Password!, user.PasswordHash, user.PasswordSalt))
        return UnauthorizedJson("Неверный никнейм или пароль");

    // Ротация refresh-токена при каждом входе
    user.RefreshToken = TokenService.CreateRefreshToken();
    user.RefreshTokenExpiry = DateTime.UtcNow.Add(TokenService.RefreshTokenLifetime);
    user.LastLoginAt = DateTime.UtcNow;
    await db.SaveChangesAsync();

    Console.WriteLine($"[Auth] Login: {user.Username}");
    return Results.Ok(new AuthResponse(tokens.CreateAccessToken(user), user.RefreshToken!, user.Id, user.Username));
});

// Продление сессии по refresh-токену (ротация токена)
auth.MapPost("/refresh", async (RefreshRequest req, AuthDbContext db, TokenService tokens) =>
{
    if (string.IsNullOrWhiteSpace(req.RefreshToken))
        return UnauthorizedJson("Нет refresh-токена");

    var user = await db.Users.FirstOrDefaultAsync(u => u.RefreshToken == req.RefreshToken);

    if (user == null || user.RefreshTokenExpiry < DateTime.UtcNow)
        return UnauthorizedJson("Сессия истекла");

    user.RefreshToken = TokenService.CreateRefreshToken();
    user.RefreshTokenExpiry = DateTime.UtcNow.Add(TokenService.RefreshTokenLifetime);
    await db.SaveChangesAsync();

    return Results.Ok(new AuthResponse(tokens.CreateAccessToken(user), user.RefreshToken!, user.Id, user.Username));
});

// Выход (аннулирование refresh-токена)
auth.MapPost("/logout", async (RefreshRequest req, AuthDbContext db) =>
{
    if (!string.IsNullOrWhiteSpace(req.RefreshToken))
    {
        var user = await db.Users.FirstOrDefaultAsync(u => u.RefreshToken == req.RefreshToken);
        if (user != null)
        {
            user.RefreshToken = null;
            user.RefreshTokenExpiry = DateTime.MinValue;
            await db.SaveChangesAsync();
            Console.WriteLine($"[Auth] Logout: {user.Username}");
        }
    }
    return Results.Ok(new { message = "ok" });
});

// Текущий пользователь (по access-токену)
auth.MapGet("/me", async (ClaimsPrincipal principal, AuthDbContext db) =>
{
    var idClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
               ?? principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
               ?? principal.FindFirst("sub")?.Value;

    if (!int.TryParse(idClaim, out var id))
        return UnauthorizedJson("Сессия недействительна");

    var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id);
    if (user == null)
        return UnauthorizedJson("Сессия недействительна");

    return Results.Ok(new MeResponse(user.Id, user.Username, user.CreatedAt, user.LastLoginAt));
}).RequireAuthorization();

// Смена пароля (нужен валидный access-токен)
auth.MapPost("/change-password", async (ChangePasswordRequest req, ClaimsPrincipal principal, AuthDbContext db) =>
{
    var idClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
               ?? principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
               ?? principal.FindFirst("sub")?.Value;

    if (!int.TryParse(idClaim, out var id))
        return UnauthorizedJson("Сессия недействительна");

    var user = await db.Users.FirstOrDefaultAsync(u => u.Id == id);
    if (user == null)
        return UnauthorizedJson("Сессия недействительна");

    if (string.IsNullOrWhiteSpace(req.CurrentPassword) || string.IsNullOrWhiteSpace(req.NewPassword))
        return Results.BadRequest(new { message = "Заполни оба поля" });

    if (!PasswordHasher.Verify(req.CurrentPassword, user.PasswordHash, user.PasswordSalt))
        return Results.BadRequest(new { message = "Неверный текущий пароль" });

    if (req.NewPassword.Length < 6)
        return Results.BadRequest(new { message = "Пароль должен быть минимум 6 символов" });
    if (req.NewPassword.Length > 64)
        return Results.BadRequest(new { message = "Пароль не может быть длиннее 64 символов" });

    var (hash, salt) = PasswordHasher.Hash(req.NewPassword);
    user.PasswordHash = hash;
    user.PasswordSalt = salt;
    await db.SaveChangesAsync();

    Console.WriteLine($"[Auth] Password changed: {user.Username}");
    return Results.Ok(new { message = "Пароль изменён" });
}).RequireAuthorization();

// Render.com задаёт порт через переменную окружения PORT
var port = Environment.GetEnvironmentVariable("PORT") ?? "10000";
Console.WriteLine($"[Auth] Listening on port {port}");
app.Run($"http://0.0.0.0:{port}");

// 401 с телом { message } — Results.Unauthorized не принимает объект
static IResult UnauthorizedJson(string message)
    => Results.Json(new { message }, statusCode: StatusCodes.Status401Unauthorized);

// ===== Валидация (те же правила, что в лаунчере) =====
static string? ValidateCredentials(string? username, string? password)
{
    var name = username?.Trim() ?? "";

    if (string.IsNullOrWhiteSpace(name))
        return "Введи никнейм";
    if (name.Length < 3 || name.Length > 16)
        return "Ник должен быть от 3 до 16 символов";
    foreach (var ch in name)
    {
        if (!(char.IsLetterOrDigit(ch) || ch == '_'))
            return "Только буквы, цифры и _";
    }

    if (string.IsNullOrWhiteSpace(password))
        return "Введи пароль";
    if (password.Length < 6)
        return "Пароль должен быть минимум 6 символов";
    if (password.Length > 64)
        return "Пароль не может быть длиннее 64 символов";

    return null;
}
