using System.Security.Claims;
using WebApi.Models;
using WebApplication1.models;
using WebApplication1.Models;

namespace WebApplication1.Utils
{
    public interface IAuthHelper
    {
        Task<TokenResult> Authenticate(Claim[] claims);
        User? Authenticate(UserLogin userLogin);
        string GenerateJwtToken(User user);
        User? GetUserByUsername(string username);
        User? GetUserById(string id);
        Task<string> RefreshToken(TokenResult tokenResult);
        Task<RefreshToken> GenerateRefreshToken(string userId);
    }
}