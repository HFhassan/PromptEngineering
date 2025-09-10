using System;
using MongoDB.Bson;
using MongoDB.Driver;

namespace BackendApi.Services
{
    public class MongoRepository
    {
        public IMongoClient Client { get; }
        public IMongoDatabase Database { get; }

        public IMongoCollection<BsonDocument> Users { get; }
        public IMongoCollection<BsonDocument> Drawings { get; }

        public MongoRepository(string? connectionString = null, string? databaseName = null)
        {
            var resolvedConnectionString = connectionString ?? Environment.GetEnvironmentVariable("MONGO_CONN");
            var resolvedDatabaseName = databaseName ?? Environment.GetEnvironmentVariable("MONGO_DB");

            if (string.IsNullOrWhiteSpace(resolvedConnectionString))
            {
                throw new InvalidOperationException("MongoDB connection string not provided. Set MONGO_CONN environment variable.");
            }

            if (string.IsNullOrWhiteSpace(resolvedDatabaseName))
            {
                throw new InvalidOperationException("MongoDB database name not provided. Set MONGO_DB environment variable.");
            }

            Client = new MongoClient(resolvedConnectionString);
            Database = Client.GetDatabase(resolvedDatabaseName);

            Users = Database.GetCollection<BsonDocument>("Users");
            Drawings = Database.GetCollection<BsonDocument>("Drawings");
        }

        public static MongoRepository FromEnvironment()
        {
            return new MongoRepository();
        }
    }
}


