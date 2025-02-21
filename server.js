// server.js - Main entry point
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
//const authRoutes = require("./routes/authRoutes");
//const profileRoutes = require("./routes/profileRoutes");
//const User = require("./models/User");

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.log(err));

// Middleware for authentication
const authMiddleware = (req, res, next) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: "Unauthorized" });
  }
};

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
});
const User = mongoose.model("User", userSchema);

// Register Route
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "Error registering user" });
  }
});

// Login Route
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    console.log(user);
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    console.log(isMatch);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    console.log(token);
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: "Error logging in" });
  }
});

// Profile Route
app.get("/api/profile", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    res.json(user);
  } catch (error) {
    res.status(401).json({ error: "Unauthorized" });
  }
});

// Update Profile Route
app.put("/api/profile", authMiddleware, async (req, res) => {
  try {
    const { name, email } = req.body;
    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      { name, email },
      { new: true }
    );
    res.json(updatedUser);
  } catch (error) {
    res.status(500).json({ error: "Error updating profile" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
