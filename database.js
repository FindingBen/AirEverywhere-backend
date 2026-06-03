const { MongoClient, ServerApiVersion } = require("mongodb");
require("dotenv").config();

const uri = process.env.MONGO_URI; // Use the environment variable

if (!uri) {
  console.error("MongoDB connection URI is missing. Check your .env file.");
  process.exit(1);
}

const isAtlas = uri.startsWith("mongodb+srv://");

// Atlas benefits from serverApi options; local MongoDB should not force TLS.
const client = new MongoClient(
  uri,
  isAtlas
    ? {
        serverApi: {
          version: ServerApiVersion.v1,
          deprecationErrors: true,
        },
      }
    : {}
);

async function connectToMongoDB() {
  try {
    await client.connect();
    console.log("Successfully connected to MongoDB!");
    const db = client.db("AirDrop");
    await db.collection("Votes").createIndex({ userId: 1, markerId: 1 }, { unique: true });
    console.log("Votes unique index created on userId + markerId");
    return client; // Return the connected client
  } catch (error) {
    console.error("Failed to connect to MongoDB:", error);
    process.exit(1); // Exit process on connection failure
  }
}

module.exports = { connectToMongoDB };
