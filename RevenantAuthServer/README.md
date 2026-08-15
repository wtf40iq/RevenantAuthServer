# Revenant Auth Server

Сервер авторизации для Revenant Launcher. ASP.NET Core 8 + SQLite + JWT.

## Эндпоинты

| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/auth/register` | Регистрация `{ username, password }` |
| POST | `/api/auth/login` | Вход `{ username, password }` |
| POST | `/api/auth/refresh` | Продление сессии `{ refreshToken }` |
| POST | `/api/auth/logout` | Выход `{ refreshToken }` |
| GET | `/api/auth/me` | Текущий пользователь (Bearer access-токен) |
| GET | `/health` | Проверка живости |

Все auth-эндпоинты ограничены rate limiter'ом: 20 запросов/мин с одного IP.

## Локальный запуск

```bash
dotnet run
```

Сервер поднимется на `http://0.0.0.0:10000` (порт можно поменять переменной `PORT`).

Тест регистрации:

```bash
curl -X POST http://localhost:10000/api/auth/register -H "Content-Type: application/json" -d "{\"username\":\"testuser\",\"password\":\"123456\"}"
```

## Деплой на Render.com

1. Загрузи этот проект в публичный репозиторий GitHub (`RevenantAuthServer`).
2. На Render: **New → Web Service** → выбери репозиторий.
3. Настройки:
   - **Runtime**: `Docker`
   - **Region**: Frankfurt
   - **Plan**: Free
4. Во вкладке **Environment** добавь переменную:
   - `JWT_SECRET` — любая случайная строка от 32 символов.
     Сгенерировать можно командой PowerShell:
     ```powershell
     -join ((48..57)+(65..90)+(97..122) | Get-Random -Count 48 | % {[char]$_})
     ```
5. **Create Web Service**. Через 2-3 минуты получишь URL вида
   `https://revenant-auth.onrender.com` — впиши его в лаунчер
   (`Services/AuthService.cs`, константа `ApiBaseUrl`).

### Важно про данные на бесплатном тарифе Render

- Файловая система бесплатного инстанса **эфемерная**: при каждом редеплое
  файл базы `data/revenant.db` сбрасывается (пользователи теряются).
- Чтобы аккаунты жили постоянно, добавь **Render Disk** (платно, ~$1/мес)
  и смонтируй его в `/app/data` — тогда база переживёт редеплои.
- Альтернатива: переехать на бесплатный PostgreSQL Render
  (поменять connection string и провайдер EF Core).

Для разработки/тестов эфемерная база не мешает.

## Безопасность

- Пароли хранятся только как **PBKDF2-SHA256** (100 000 итераций, соль на пользователя).
- Access-токен (JWT) — 15 минут. Refresh-токен — 30 дней, ротация при каждом использовании.
- `JWT_SECRET` **обязательно** задай через переменную окружения на сервере.
