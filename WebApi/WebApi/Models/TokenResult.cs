using WebApplication1.models;

namespace WebApi.Models
{
    public class TokenResult
    {
        public string Token { get; set; } = string.Empty;

        public string RefreshToken { get; set; } = string.Empty;
    }
}
