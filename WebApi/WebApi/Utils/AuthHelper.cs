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
                new Claim("Username", user.Username),
                new Claim("UserId", user.Id)
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
                Id = apiUser.First().Id,
                Username = apiUser.First().Username,
                Password = apiUser.First().Password,
            };

            return user;
        }

        public async Task<RefreshToken> GenerateRefreshToken(string userId)
        {
            await RevokeAllRefreshToken(userId);

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

        public async Task RevokeAllRefreshToken(string userId)
        {
            var userBuilder = Builders<RefreshTokenDb>.Filter;
            var userIdFilter = userBuilder.Eq("UserId", userId);
            await _refreshToken.DeleteManyAsync(userIdFilter);
        }

        public async Task<TokenResult> RefreshToken(TokenResult tokenResult)
        {
            try
            {
                var builder = Builders<RefreshTokenDb>.Filter;
                var filter = builder.Eq("Token", tokenResult.RefreshToken);
                var refreshTokenDb = await _refreshToken.FindAsync(filter);

                if (refreshTokenDb.First().Token != tokenResult.RefreshToken)
                {
                    throw new SecurityTokenException("Token is invalid.");
                }
            }
            catch (Exception)
            {
                throw new SecurityTokenException("Token is invalid.");
            }


            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(tokenResult.Token);
            var username = jwtSecurityToken.Claims.First(claim => claim.Type == "Username").Value;
            var userId = jwtSecurityToken.Claims.First(claim => claim.Type == "UserId").Value;

            var user = new User
            {
                Id = userId,
                Username = username
            };

            await RevokeAllRefreshToken(user.Id);

            var token = GenerateJwtToken(user);

            var refreshToken = await GenerateRefreshToken(user.Id);

            var result = new TokenResult
            {
                Token = token,
                RefreshToken = refreshToken.Token
            };

            return result;
        }
    }
}
