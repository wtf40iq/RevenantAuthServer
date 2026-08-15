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

// Первая строка — подтверждаем, что процесс вообще стартовал
Console.WriteLine("[Auth] Boot started");

// Печатаем ЛЮБОЕ необработанное исключение в stderr, чтобы Render показал причину
AppDomain.CurrentDomain.UnhandledException += (_, e) =>
    Console.Error.WriteLine("[Auth] UNHANDLED: " + e.ExceptionObject);

// На некоторых хостах (Render free) исчерпан лимит inotify —
// отключаем слежку за файлами конфигурации до создания builder'а
Environment.SetEnvironmentVariable("DOTNET_hostBuilder__reloadConfigOnChange", "false");
Environment.SetEnvironmentVariable("DOTNET_USE_POLLING_FILE_WATCHER", "1");

var builder = WebApplication.CreateBuilder(args);
// ... existing code ...
