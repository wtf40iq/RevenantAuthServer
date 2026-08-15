// ... existing code ...
using RevenantAuthServer.Data;
using RevenantAuthServer.Models;
using RevenantAuthServer.Services;

// На некоторых хостах (Render free) исчерпан лимит inotify —
// отключаем слежку за файлами конфигурации до создания builder'а,
// иначе краш IOException при старте
Environment.SetEnvironmentVariable("DOTNET_hostBuilder__reloadConfigOnChange", "false");
Environment.SetEnvironmentVariable("DOTNET_USE_POLLING_FILE_WATCHER", "1");

var builder = WebApplication.CreateBuilder(args);
// ... existing code ...
