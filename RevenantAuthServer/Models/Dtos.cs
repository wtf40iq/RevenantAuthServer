namespace RevenantAuthServer.Models
{
    public record RegisterRequest(string? Username, string? Password);
    public record LoginRequest(string? Username, string? Password);
    public record RefreshRequest(string? RefreshToken);
    public record ChangePasswordRequest(string? CurrentPassword, string? NewPassword);

    public record AuthResponse(string AccessToken, string RefreshToken, int UserId, string Username);
    public record MeResponse(int UserId, string Username, DateTime CreatedAt, DateTime LastLoginAt);
}
