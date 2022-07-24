using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApplication1.models;
using WebApplication1.Models;
using WebApplication1.Utils;

namespace WebApplication1.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IMongoCollection<User> _users;
        public UserController(IMongoClient client)
        {
            var database = client.GetDatabase("Calendar");
            var collection = database.GetCollection<User>("user");
            _users = collection;
        }

        [HttpPost("/login")]
        public IActionResult Login([FromBody] UserLogin userLogin)
        {
            var user = Authenticate(userLogin);

            if (user != null)
            {
                var token = Generate(user);
                return Ok(token);
            }

            return BadRequest("Wrong username or password!");
        }

        private string Generate(User user)
        {
            string key = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build().GetSection("jwt")["Key"];
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim("Username", user.Username)
            };

            string issuer = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build().GetSection("jwt")["Issuer"];
            string audience = new ConfigurationBuilder().AddJsonFile("appsettings.json").Build().GetSection("jwt")["Audience"];
            var token = new JwtSecurityToken(issuer, audience, claims, expires: DateTime.Now.AddMinutes(10), signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private User? Authenticate(UserLogin userLogin)
        {
            var builder = Builders<User>.Filter;
            var filter = builder.Eq("Username", userLogin.Username.ToLower());
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

            bool verify = AuthHelper.VerifyPassword(userLogin.Password, user.Password);

            if (verify)
            {
                return user;
            }

            return null;

        }

        [HttpPost("/register")]
        public async Task<IActionResult> PostAsync([FromBody] UserLogin userLogin)
        {
            try
            {
                // Try find if username already exists, throw bad request


                // Validate password and username length
                var hashedPassword = AuthHelper.GetHashedPassword(userLogin.Password);
                var user = new User { Password = hashedPassword, Username = userLogin.Username.ToLower() };
                await _users.InsertOneAsync(user);

                return Ok();
            }
            catch (Exception)
            {
                return BadRequest();
            }

        }
    }
}