using MongoDB.Bson.Serialization.Attributes;

namespace WebApplication1.models
{
    public class User
    {
        [BsonId]
        public int Id { get; set; }

        public string Username { get; set; }

        public string Password { get; set; }
    }
}
