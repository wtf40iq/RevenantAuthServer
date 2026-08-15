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

// Логируем в stderr с flush — stdout на Render может теряться при SIGKILL
static void Log(string message)
{
    Console.Error.WriteLine(message);
    Console.Error.Flush();
}

AppDomain.CurrentDomain.UnhandledException += (_, e) => Log("[Auth] UNHANDLED: " + e.ExceptionObject);

Log("[Auth] phase: boot");

// Render free: исчерпан лимит inotify — отключаем слежку за конфиг-файлами
Environment.SetEnvironmentVariable("DOTNET_hostBuilder__reloadConfigOnChange", "false");
Environment.SetEnvironmentVariable("DOTNET_USE_POLLING_FILE_WATCHER", "1");
Log("[Auth] phase: env set");

try
{
    var builder = WebApplication.CreateBuilder(args);
    Log("[Auth] phase: builder created");

    var jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET")
        ?? builder.Configuration["Jwt:Secret"];

    if (string.IsNullOrWhiteSpace(jwtSecret) || Encoding.UTF8.GetByteCount(jwtSecret) < 32)
    {
        Log("[Auth] WARNING: JWT_SECRET не задан/короткий — использую dev-секрет");
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
    Log("[Auth] phase: services registered");

    var app = builder.Build();
    Log("[Auth] phase: app built");

    Directory.CreateDirectory("data");
    using (var scope = app.Services.CreateScope())
        scope.ServiceProvider.GetRequiredService<AuthDbContext>().Database.EnsureCreated();
    Log("[Auth] phase: db ready");

    app.UseCors();
    app.UseRateLimiter();
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapGet("/", () => Results.Ok(new { name = "Revenant Auth Server", status = "ok" }));
    app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

    var auth = app.MapGroup("/api/auth").RequireRateLimiting("auth");

    auth.MapPost("/register", async (RegisterRequest req, AuthDbContext db, TokenService tokens) =>
    {
        var error = ValidateCredentials(req.Username, req.Password);
        if (error != null) return Results.BadRequest(new { message = error });

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
        Log($"[Auth] Registered: {username} (id={user.Id})");
        return Results.Ok(new AuthResponse(tokens.CreateAccessToken(user), user.RefreshToken!, user.Id, user.Username));
    });

    auth.MapPost("/login", async (LoginRequest req, AuthDbContext db, TokenService tokens) =>
    {
        if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
            return Results.BadRequest(new { message = "Введи никнейм и пароль" });

        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == req.Username.Trim());
        if (user == null || !PasswordHasher.Verify(req.Password!, user.PasswordHash, user.PasswordSalt))
            return UnauthorizedJson("Неверный никнейм или пароль");

        user.RefreshToken = TokenService.CreateRefreshToken();
        user.RefreshTokenExpiry = DateTime.UtcNow.Add(TokenService.RefreshTokenLifetime);
        user.LastLoginAt = DateTime.UtcNow;
        await db.SaveChangesAsync();

        Log($"[Auth] Login: {user.Username}");
        return Results.Ok(new AuthResponse(tokens.CreateAccessToken(user), user.RefreshToken!, user.Id, user.Username));
    });

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
                Log($"[Auth] Logout: {user.Username}");
            }
        }
        return Results.Ok(new { message = "ok" });
    });

    auth.MapGet("/me", (ClaimsPrincipal principal) =>
    {
        var idClaim = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value
                   ?? principal.FindFirst(JwtRegisteredClaimNames.Sub)?.Value
                   ?? principal.FindFirst("sub")?.Value;
        var username = principal.FindFirst("username")?.Value ?? "";
        return Results.Ok(new MeResponse(int.TryParse(idClaim, out var id) ? id : 0, username));
    }).RequireAuthorization();

    var port = Environment.GetEnvironmentVariable("PORT") ?? "10000";
    Log($"[Auth] phase: listening on port {port}");
    app.Run($"http://0.0.0.0:{port}");
}
catch (Exception ex)
{
    Log("[Auth] FATAL: " + ex);
    throw;
}

static IResult UnauthorizedJson(string message)
    => Results.Json(new { message }, statusCode: StatusCodes.Status401Unauthorized);

static string? ValidateCredentials(string? username, string? password)
{
    var name = username?.Trim() ?? "";
    if (string.IsNullOrWhiteSpace(name)) return "Введи никнейм";
    if (name.Length < 3 || name.Length > 16) return "Ник должен быть от 3 до 16 символов";
    foreach (var ch in name)
        if (!(char.IsLetterOrDigit(ch) || ch == '_')) return "Только буквы, цифры и _";

    if (string.IsNullOrWhiteSpace(password)) return "Введи пароль";
    if (password.Length < 6) return "Пароль должен быть минимум 6 символов";
    if (password.Length > 64) return "Пароль не может быть длиннее 64 символов";
    return null;
}
