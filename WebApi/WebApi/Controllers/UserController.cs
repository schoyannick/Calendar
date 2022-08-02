using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MongoDB.Driver;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApi.Models;
using WebApplication1.models;
using WebApplication1.Models;
using WebApplication1.Utils;

namespace WebApplication1.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IAuthHelper _authHelper;
        private readonly IMongoCollection<User> _users;

        public UserController(IMongoClient client, IAuthHelper authHelper)
        {
            var database = client.GetDatabase("Calendar");
            var userCollection = database.GetCollection<User>("user");
            _users = userCollection;

            _authHelper = authHelper;
        }

        [HttpPost("/login")]
        async public Task<IActionResult> Login([FromBody] UserLogin userLogin)
        {
            var user = _authHelper.Authenticate(userLogin);

            if (user == null)
            {
                return BadRequest("Wrong username or password!");
            }

            var token = _authHelper.GenerateJwtToken(user);

            var refreshToken = await _authHelper.GenerateRefreshToken(user.Id);

            var result = new TokenResult
            {
                Token = token,
                RefreshToken = refreshToken.Token
            };

            return Ok(result);
        }

        [HttpPost("/register")]
        public async Task<IActionResult> PostAsync([FromBody] UserLogin userLogin)
        {
            try
            {
                // Try find if username already exists, throw bad request
                var existingUser = _authHelper.GetUserByUsername(userLogin.Username);
                if (existingUser != null)
                {
                    return Conflict("Username does already exist.");
                }

                // Username is to short
                if (userLogin.Username.Length < 3)
                {
                    return Conflict("Username needs to have at least 3 characters.");
                }

                // Password is to short
                if (userLogin.Password.Length < 5)
                {
                    return Conflict("Password needs to have at least 5 characters.");
                }

                var hashedPassword = AuthHelper.GetHashedPassword(userLogin.Password);
                var user = new User { Password = hashedPassword, Username = userLogin.Username.ToLower() };

                await _users.InsertOneAsync(user);

                var token = _authHelper.GenerateJwtToken(user);

                var refreshToken = await _authHelper.GenerateRefreshToken(user.Id);

                var result = new TokenResult
                {
                    Token = token,
                    RefreshToken = refreshToken.Token
                };

                return Ok(result);
            }
            catch (Exception e)
            {
                return BadRequest(e);
            }

        }

        [HttpPost("/refresh")]
        public IActionResult Refresh([FromBody] TokenResult tokenResult)
        {
            try
            {
                var token = _authHelper.RefreshToken(tokenResult);

                return Ok(token);
            }
            catch (Exception e)
            {
                return BadRequest(e);
            }

        }

        [HttpGet("/pog")]
        [Authorize]
        public IActionResult Pog()
        {
            return Ok("Pog");
        }
    }
}