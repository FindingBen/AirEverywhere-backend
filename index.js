const { connectToMongoDB, dbName } = require("./database");
const { ObjectId } = require("mongodb");

const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { S3Client, GetObjectCommand, PutObjectCommand } = require("@aws-sdk/client-s3");
const port = process.env.PORT || 5001;
const jwtSecret = process.env.JWT_SECRET || "your_jwt_secret";
const jwtExpiresIn = "30d";
const s3Bucket = process.env.S3_BUCKET || "erforus-pump-location-raw";
const awsRegion = process.env.AWS_REGION || "us-east-1";
const s3Client = new S3Client({ region: awsRegion });
const app = express();

app.use(express.json());
app.use(cors({
  origin: "*", // Allow all origins (adjust for production as needed)
}));

let db; // Declare db at module level

const createAuthToken = (userId) =>
  jwt.sign({ userId: userId.toString() }, jwtSecret, {
    expiresIn: jwtExpiresIn,
  });

const generateAnonymousUsername = () => `user${Math.floor(100000 + Math.random() * 900000)}`;

const createAnonymousUser = async (usersCollection, installId) => {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const username = generateAnonymousUsername();
    const existingUsername = await usersCollection.findOne({ username });

    if (existingUsername) {
      continue;
    }

    const now = new Date();
    const newUser = {
      username,
      installId,
      isAnonymous: true,
      contributionPoints: 0,
      createdAt: now,
      lastSeenAt: now,
    };

    const result = await usersCollection.insertOne(newUser);

    return {
      ...newUser,
      _id: result.insertedId,
    };
  }

  throw new Error("Failed to generate anonymous username.");
};

connectToMongoDB().then((client) => {
  db = client.db(dbName);
  console.log("MongoDB connection established for Express app.");
  console.log(`Express app using database: ${dbName}`);
  
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
      isAdmin: false,
      contributionPoints: 0,
      password: hashedPassword,
    };
    const result = await db.collection("Users").insertOne(newUser);
    console.log('REGISTERED!')
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
    const token = createAuthToken(user._id);

    res.json({
      message: "Login successful",
      token,
      userId: user._id.toString(),
      username: user.username,
      isAnonymous: Boolean(user.isAnonymous),
    });
  } catch (error) {
    console.error("Error logging in user:", error);
    res.status(500).send("An error occurred while logging in.");
  }
});

app.post("/auth/anonymous", async (req, res) => {
  try {
    const { installId } = req.body;

    if (!installId) {
      return res.status(400).json({ error: "installId is required." });
    }

    const usersCollection = db.collection("Users");
    let user = await usersCollection.findOne({ installId, isAnonymous: true });

    if (!user) {
      user = await createAnonymousUser(usersCollection, installId);
    } else {
      await usersCollection.updateOne(
        { _id: user._id },
        { $set: { lastSeenAt: new Date() } }
      );

      user.lastSeenAt = new Date();
    }

    const token = createAuthToken(user._id);

    res.json({
      message: "Anonymous user ready",
      token,
      userId: user._id.toString(),
      username: user.username,
      isAnonymous: true,
    });
  } catch (error) {
    console.error("Error creating anonymous user:", error);
    res.status(500).json({ error: "An error occurred while creating anonymous user." });
  }
});

const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    return res.status(403).json({ error: "No token provided." });
  }

  jwt.verify(token, jwtSecret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Invalid or expired token." });
    }
    req.user = decoded; // Attach user info to the request
    next();
  });
};

const getRequestUserId = (req) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return req.body?.userId || req.query?.userId;
  }

  try {
    const decoded = jwt.verify(token, jwtSecret);
    return decoded.userId;
  } catch (error) {
    return null;
  }
};

app.get("/me", async (req, res) => {
  try {
    const userId = getRequestUserId(req);

    if (!userId || !ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Valid user id or token is required." });
    }

    const user = await db.collection("Users").findOne(
      { _id: new ObjectId(userId) },
      {
        projection: {
          username: 1,
          contributionPoints: 1,
          isAnonymous: 1,
          isAdmin: 1,
          email: 1,
        },
      }
    );

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({
      userId: user._id.toString(),
      username: user.username,
      contributionPoints: user.contributionPoints || 0,
      isAnonymous: Boolean(user.isAnonymous),
      isAdmin: Boolean(user.isAdmin ?? false),
      email: user.email || null,
    });
  } catch (error) {
    console.error("Error fetching current user:", error);
    res.status(500).json({ error: "An error occurred while fetching the user." });
  }
});

app.post("/reviews", async (req, res) => {
  try {
    const userId = getRequestUserId(req);
    const { text } = req.body;

    if (!userId || !ObjectId.isValid(userId)) {
      return res.status(400).json({ error: "Valid user id or token is required." });
    }

    if (typeof text !== "string") {
      return res.status(400).json({ error: "Review text is required." });
    }

    const trimmedText = text.trim();

    if (!trimmedText) {
      return res.status(400).json({ error: "Review text is required." });
    }

    if (trimmedText.length > 500) {
      return res.status(400).json({ error: "Review must be 500 characters or less." });
    }

    const userObjectId = new ObjectId(userId);
    const user = await db.collection("Users").findOne(
      { _id: userObjectId },
      { projection: { username: 1, isAnonymous: 1, email: 1 } }
    );

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const review = {
      userId: userObjectId,
      username: user.username,
      isAnonymous: Boolean(user.isAnonymous),
      email: user.email || null,
      text: trimmedText,
      createdAt: new Date(),
    };

    const result = await db.collection("Reviews").insertOne(review);

    res.status(201).json({
      message: "Review submitted successfully.",
      reviewId: result.insertedId.toString(),
    });
  } catch (error) {
    console.error("Error creating review:", error);
    res.status(500).json({ error: "An error occurred while submitting the review." });
  }
});

app.get("/markers", async (req, res) => {
  try {
    const markersCollection = db.collection("Markers");
    const markers = await markersCollection
      .find({})
      .map((marker) => ({
        ...marker,
        _id: marker._id.toString(), // Return _id as string
      }))
      .toArray();
    
    res.json(markers);
    console.log('request made!')
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

app.post(
  "/markers/:markerId/image",
  verifyToken,
  express.raw({ type: ["image/jpeg", "image/png", "image/webp"], limit: "10mb" }),
  async (req, res) => {
    try {
      const { markerId } = req.params;
      const contentType = req.headers["content-type"];

      if (!ObjectId.isValid(markerId)) {
        return res.status(400).json({ error: "Invalid marker id." });
      }

      if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
        return res.status(400).json({ error: "An image file is required." });
      }

      const markerObjectId = new ObjectId(markerId);
      const markersCollection = db.collection("Markers");
      const marker = await markersCollection.findOne({ _id: markerObjectId });

      if (!marker) {
        return res.status(404).json({ error: "Pump not found." });
      }

      if (marker.imageUrl) {
        return res.status(409).json({ error: "Updated pump photos must be submitted for approval." });
      }

      const key = `markers/${markerId}/pump-image`;
      await s3Client.send(new PutObjectCommand({
        Bucket: s3Bucket,
        Key: key,
        Body: req.body,
        ContentType: contentType,
      }));

      const imageUrl = `/markers/${markerId}/image`;
      await markersCollection.updateOne(
        { _id: markerObjectId },
        { $set: { imageUrl, imageUpdatedAt: new Date() } }
      );

      res.status(200).json({ imageUrl });
    } catch (error) {
      console.error("Error uploading pump image:", error);
      res.status(500).json({ error: "An error occurred while uploading the pump image." });
    }
  }
);

app.post(
  "/markers/:markerId/image-submissions",
  verifyToken,
  express.raw({ type: ["image/jpeg", "image/png", "image/webp"], limit: "10mb" }),
  async (req, res) => {
    try {
      const { markerId } = req.params;
      const contentType = req.headers["content-type"];

      if (!ObjectId.isValid(markerId)) {
        return res.status(400).json({ error: "Invalid marker id." });
      }

      if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
        return res.status(400).json({ error: "An image file is required." });
      }

      const userId = req.user.userId;
      if (!ObjectId.isValid(userId)) {
        return res.status(403).json({ error: "Invalid user token." });
      }

      const user = await db.collection("Users").findOne(
        { _id: new ObjectId(userId) },
        { projection: { username: 1, isAnonymous: 1 } }
      );
      if (!user || user.isAnonymous) {
        return res.status(403).json({ error: "A registered account is required to submit a photo." });
      }

      const markerObjectId = new ObjectId(markerId);
      const markersCollection = db.collection("Markers");
      const marker = await markersCollection.findOne({ _id: markerObjectId });
      if (!marker) {
        return res.status(404).json({ error: "Pump not found." });
      }

      const submittedAt = new Date();
      if (!marker.imageUrl) {
        const key = `markers/${markerId}/pump-image`;
        await s3Client.send(new PutObjectCommand({
          Bucket: s3Bucket,
          Key: key,
          Body: req.body,
          ContentType: contentType,
        }));

        const imageUrl = `/markers/${markerId}/image`;
        await markersCollection.updateOne(
          { _id: markerObjectId },
          { $set: { imageUrl, imageUpdatedAt: submittedAt } }
        );

        return res.status(201).json({
          message: "Pump photo added successfully.",
          imageUrl,
          status: "approved",
        });
      }

      const submissionId = new ObjectId();
      const key = `image-submissions/${submissionId.toString()}`;
      await s3Client.send(new PutObjectCommand({
        Bucket: s3Bucket,
        Key: key,
        Body: req.body,
        ContentType: contentType,
      }));

      await db.collection("ImageSubmissions").insertOne({
        _id: submissionId,
        markerId: markerObjectId,
        pumpName: marker.name,
        contributor: user.username,
        userId: user._id,
        s3Key: key,
        contentType,
        status: "pending",
        submittedAt,
      });

      res.status(201).json({
        message: "Your photo is waiting for admin approval.",
        submissionId: submissionId.toString(),
        status: "pending",
      });
    } catch (error) {
      console.error("Error submitting pump image:", error);
      res.status(500).json({ error: "An error occurred while submitting the pump image." });
    }
  }
);

app.get("/markers/:markerId/image", async (req, res) => {
  try {
    const { markerId } = req.params;

    if (!ObjectId.isValid(markerId)) {
      return res.status(400).json({ error: "Invalid marker id." });
    }

    const image = await s3Client.send(new GetObjectCommand({
      Bucket: s3Bucket,
      Key: `markers/${markerId}/pump-image`,
    }));

    res.set("Content-Type", image.ContentType || "application/octet-stream");
    res.set("Cache-Control", "no-cache");
    image.Body.pipe(res);
  } catch (error) {
    if (error.name === "NoSuchKey" || error.name === "NotFound") {
      return res.status(404).json({ error: "Pump image not found." });
    }

    console.error("Error retrieving pump image:", error);
    res.status(500).json({ error: "An error occurred while retrieving the pump image." });
  }
});

app.post("/vote", async (req, res) => {
  try {
    const voteCollection = db.collection("Votes");
    const { markerId, voteType, pointsAwarded } = req.body;
    const userId = getRequestUserId(req);

    // Validate all required fields
    if (!userId || !markerId || !voteType || pointsAwarded === undefined) {
      return res.status(400).json({ error: "All fields required!" });
    }

    if (!ObjectId.isValid(userId) || !ObjectId.isValid(markerId)) {
      return res.status(400).json({ error: "Invalid user or marker id." });
    }

    if (!["upvote", "downvote"].includes(voteType)) {
      return res.status(400).json({ error: "Invalid vote type." });
    }
    
    // Convert string IDs to ObjectId for database queries
    const userObjectId = new ObjectId(userId);
    const markerObjectId = new ObjectId(markerId);

    const existingVote = await voteCollection.findOne({
      userId: userObjectId,
      markerId: markerObjectId,
    });

    if (existingVote) {
      return res.status(409).json({
        error: "You already gave feedback on this pump.",
        existingVoteType: existingVote.voteType,
      });
    }

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
    if (error.code === 11000 || error.message.includes("E11000")) {
      return res.status(409).json({ 
        error: "You already gave feedback on this pump." 
      });
    }

    console.error("Error adding vote:", error.message, error.code);
    console.error("Full error object:", error);
    
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

app.get("/health", async (req, res) => {
  try {
    await db.command({ ping: 1 });

    res.json({
      ok: true,
      database: dbName,
      message: "MongoDB connection is healthy.",
    });
  } catch (error) {
    console.error("Health check failed:", error);
    res.status(500).json({
      ok: false,
      database: dbName,
      error: "MongoDB ping failed.",
    });
  }
});
