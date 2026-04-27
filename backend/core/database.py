from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure
from dotenv import load_dotenv
import os

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "secuintell")

client: MongoClient = None
db = None

def connect_db():
    """Initialize MongoDB Atlas connection and create indexes."""
     print(f"DEBUG MONGO_URI = {MONGO_URI}")
    global client, db
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        # Verify connection
        client.admin.command("ping")
        db = client[DB_NAME]

        # Indexes for performance on the logs collection
        db["logs"].create_index([("timestamp", DESCENDING)])
        db["logs"].create_index([("level", ASCENDING)])
        db["logs"].create_index([("source_ip", ASCENDING)])
        db["logs"].create_index([("event_type", ASCENDING)])

        print(f"✅ Connected to MongoDB Atlas — database: '{DB_NAME}'")
    except ConnectionFailure as e:
        print(f"❌ MongoDB connection failed: {e}")
        raise

def disconnect_db():
    """Close the MongoDB connection."""
    global client
    if client:
        client.close()
        print("🔌 MongoDB connection closed.")


def get_db():
    """Return the active database instance."""
    if db is None:
        raise RuntimeError("Database not initialised. Call connect_db() first.")
    return db
