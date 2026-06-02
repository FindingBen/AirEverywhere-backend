const { connectToMongoDB } = require("./database");
const { ObjectId } = require("mongodb");

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const port = 5001;
const app = express();

app.use(express.json());
app.use(cors({
  origin: "*", // Allow all origins (adjust for production as needed)
}));

let db; // Declare db at module level

connectToMongoDB().then((client) => {
  db = client.db("AirDrop");
  console.log("MongoDB connection established for Express app.");
  
  // Start server only after MongoDB is connected
  app.listen(port, () => {
    console.log(`Server running on Port:${port}`);
  });
}).catch((error) => {
  console.error("Failed to connect to MongoDB:", error);
  process.exit(1);
});

app.post("/register", async (req, res) => {
  try {
    const { email, password, username } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "All fields are required." });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Please provide a valid email address." });
    }

    // Check if user already exists
    const existingUser = await db.collection("Users").findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "User already exists." });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = {
      email: email,
      username: username,
      contributionPoints: 0,
      password: hashedPassword,
    };
    const result = await db.collection("Users").insertOne(newUser);
    res.json({ message: "User registered successfully!" });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).send("An error occurred while registering the user.");
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "All fields are required." });
    }

    // Find user by email
    const user = await db.collection("Users").findOne({ email });
    if (!user) {
      return res.status(400).json({ error: "Invalid credentials." });
    }

    // Compare password with stored hash
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials." });
    }

    // Create JWT token
    const token = jwt.sign({ userId: user._id }, "your_jwt_secret", {
      expiresIn: "1h",
    });

    res.json({ message: "Login successful", token });
  } catch (error) {
    console.error("Error logging in user:", error);
    res.status(500).send("An error occurred while logging in.");
  }
});

const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    return res.status(403).json({ error: "No token provided." });
  }

  jwt.verify(token, "your_jwt_secret", (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token." });
    }
    req.user = decoded; // Attach user info to the request
    next();
  });
};

app.get("/markers", async (req, res) => {
  try {
    const markersCollection = db.collection("Markers"); // Replace with your collection name
    const markers = await markersCollection
      .find({})
      .map((marker) => ({
        ...marker,
        id: marker._id.toString(), // Convert ObjectId to string
      }))
      .toArray();
    
    res.json(markers);
  } catch (error) {
    console.error("Error fetching markers:", error);
    res.status(500).send("An error occurred while fetching markers.");
  }
});

app.post("/markers", async (req, res) => {
  try {
    const markersCollection = db.collection("Markers");
    const { latitude, longitude, name, status } = req.body;

    if (!latitude || !longitude || !name || !status) {
      return res.status(400).json({ error: "All fields are required." });
    }
    const newMarker = {
      latitude,
      longitude,
      name,
      status,
      positive: 0,
      negative: 0
    };
    const result = await markersCollection.insertOne(newMarker);
    res.json({ message: "Marker added successfully!", id: result.insertedId });
  } catch (error) {
    console.error("Error adding marker:", error);
    res.status(500).send("An error occurred while adding the marker.");
  }
});

app.post("/vote", async (req, res) => {
  try {
    const voteCollection = db.collection("Votes");
    const { userId, markerId, voteType, pointsAwarded } = req.body;

    // Validate all required fields
    if (!userId || !markerId || !voteType || pointsAwarded === undefined) {
      return res.status(400).json({ error: "All fields required!" });
    }
    console.log(req.body)
    // Convert string IDs to ObjectId for database queries
    const userObjectId = new ObjectId(userId);
    const markerObjectId = new ObjectId(markerId);

    const voteObject = {
      userId: userObjectId,
      markerId: markerObjectId,
      voteType,
      pointsAwarded,
      timestamp: new Date()
    };

    const result = await voteCollection.insertOne(voteObject);
    
    // Update marker feedback counts
    const markersCollection = db.collection("Markers");
    const updateField = voteType === "upvote" ? "positive" : "negative";
    await markersCollection.updateOne(
      { _id: markerObjectId },
      { $inc: { [updateField]: 1 } }
    );
    
    // Update user contribution points
const usersCollection = db.collection("Users");
const userUpdateResult = await usersCollection.updateOne(
  { _id: userObjectId },
  { $inc: { contributionPoints: pointsAwarded } }  // ← Use pointsAwarded instead of 5
);
    
    console.log("User update result:", userUpdateResult);
    console.log("Updated userId:", userObjectId.toString());
    
    res.json({ message: "Thank you for the feedback!", id: result.insertedId });

  } catch (error) {
    console.error("Error adding vote:", error.message, error.code);
    console.error("Full error object:", error);
    
    // Check for duplicate key error (user already voted on this pump)
    if (error.code === 11000 || error.message.includes("E11000")) {
      console.log("Duplicate key detected, sending 409 response");
      return res.status(409).json({ 
        error: "You already gave your feedback on this pump. You can vote again in a week if the pump's status changes." 
      });
    }
    
    console.log("Sending 500 error response");
    res.status(500).json({ error: "An error occurred while sending your feedback." });
  }
});

app.get("/users", async (req, res) => {
  try {
    const users = await db.collection("Users")
      .find({})
      .project({ username: 1, contributionPoints: 1 })
      .toArray();
    
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "An error occurred while fetching users." });
  }
});

app.get("/", (req, res) => {
  res.send("Yo from API!");
});
