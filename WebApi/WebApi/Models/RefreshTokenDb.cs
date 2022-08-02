using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using WebApplication1.models;

namespace WebApi.Models
{
    public class RefreshTokenDb : RefreshToken
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }

        public string UserId { get; set; }
    }
}
