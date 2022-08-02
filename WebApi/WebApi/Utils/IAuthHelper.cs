using System.Security.Claims;
using WebApi.Models;
using WebApplication1.models;
using WebApplication1.Models;

namespace WebApplication1.Utils
{
    public interface IAuthHelper
    {
        User? Authenticate(UserLogin userLogin);
        string GenerateJwtToken(User user);
        User? GetUserByUsername(string username);
        Task<TokenResult> RefreshToken(TokenResult tokenResult);
        Task<RefreshToken> GenerateRefreshToken(string userId);
        Task RevokeAllRefreshToken(string userId);
    }
}