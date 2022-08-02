using BCrypt;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApi.Models;
using WebApplication1.models;
using WebApplication1.Models;

namespace WebApplication1.Utils
{
    public class AuthHelper : IAuthHelper
    {
        private readonly IConfiguration _config;
        private readonly IMongoCollection<User> _users;
        private readonly IMongoCollection<RefreshTokenDb> _refreshToken;

        public AuthHelper(IConfiguration config, IMongoClient client)
        {
            _config = config;

            var database = client.GetDatabase("Calendar");
            var userCollection = database.GetCollection<User>("user");
            _users = userCollection;

            var refreshTokenCollection = database.GetCollection<RefreshTokenDb>("refreshToken");
            _refreshToken = refreshTokenCollection;
        }
        public static string GetHashedPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        public static bool VerifyPassword(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }

        public string GenerateJwtToken(User user)
        {
            string key = _config.GetSection("jwt").GetSection("Key").Value;
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim("Username", user.Username)
            };

            string issuer = _config.GetSection("jwt").GetSection("Issuer").Value;
            string audience = _config.GetSection("jwt").GetSection("Audience").Value;
            var token = new JwtSecurityToken(issuer, audience, claims, expires: DateTime.Now.AddMinutes(10), signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public User? GetUserByUsername(string username)
        {
            var builder = Builders<User>.Filter;
            var filter = builder.Eq("Username", username.ToLower());
            var apiUser = _users.Find(filter);

            if (apiUser.CountDocuments() == 0)
            {
                return null;
            }

            var user = new User()
            {
                Username = apiUser.First().Username,
                Password = apiUser.First().Password,
            };

            return user;
        }

        public async Task<RefreshToken> GenerateRefreshToken(string userId)
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.Now.AddDays(30),
                Created = DateTime.Now
            };

            // Store in database
            var refreshTokenDb = new RefreshTokenDb
            {
                UserId = userId,
                Created = refreshToken.Created,
                Expires = refreshToken.Expires,
                Token = refreshToken.Token
            };
            await _refreshToken.InsertOneAsync(refreshTokenDb);

            return refreshToken;
        }

        public User? Authenticate(UserLogin userLogin)
        {
            var user = GetUserByUsername(userLogin.Username);

            if (user == null)
            {
                return null;
            }

            bool verify = VerifyPassword(userLogin.Password, user.Password);

            if (verify)
            {
                return user;
            }

            return null;
        }

        async public Task<TokenResult> Authenticate(Claim[] claims)
        {
            string key = _config.GetSection("jwt").GetSection("Key").Value;
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var jwtSecurityToken = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddMinutes(10), signingCredentials: credentials);

            var token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

            var refreshToken = await GenerateRefreshToken("");

            var result = new TokenResult
            {
                Token = token,
                RefreshToken = refreshToken.Token
            };

            return result;
        }

        public async Task<string> RefreshToken(TokenResult tokenResult)
        {
            string key = _config.GetSection("jwt").GetSection("Key").Value;
            string issuer = _config.GetSection("jwt").GetSection("Issuer").Value;
            string audience = _config.GetSection("jwt").GetSection("Audience").Value;

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken validatedToken;
            var principal = tokenHandler.ValidateToken(tokenResult.Token,
                new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidateIssuer = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = issuer,
                    ValidAudience = audience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
                }, out validatedToken);
            var jwtToken = validatedToken as JwtSecurityToken;

            if (jwtToken == null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256))
            {
                throw new SecurityTokenException("Token is invalid.");
            }

            var builder = Builders<RefreshTokenDb>.Filter;
            var filter = builder.Eq("Token", tokenResult.RefreshToken);
            var refreshTokenDb = (await _refreshToken.FindAsync(filter)).First();
            if (refreshTokenDb.Token != tokenResult.RefreshToken)
            {
                throw new SecurityTokenException("Token is invalid.");
            }

            //var user = GetUserByUsername()

            //return GenerateJwtToken(user);
            return "10";
        }

        public User? GetUserById(string id)
        {
            throw new NotImplementedException();
        }
    }
}
