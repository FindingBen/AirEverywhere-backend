const { connectToMongoDB } = require("./database");

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const port = 5000;
const app = express();

app.use(express.json());
cors({
  origin: "*", // Allow all origins (adjust for production as needed)
});

connectToMongoDB().then((client) => {
  db = client.db("Airdrop"); // Replace with your database name
  console.log("MongoDB connection established for Express app.");
});

app.post("/register", async (req, res) => {
  try {
    console.log(req.body);
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: "All fields are required." });
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
    console.log("AA", markers);
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
    };
    const result = await markersCollection.insertOne(newMarker);
    res.json({ message: "Marker added successfully!", id: result.insertedId });
  } catch (error) {
    console.error("Error adding marker:", error);
    res.status(500).send("An error occurred while adding the marker.");
  }
});

app.get("/", (req, res) => {
  res.send("Yo from API!");
});

app.listen(port, () => {
  console.log(`Server running on Port:${port}`);
});
