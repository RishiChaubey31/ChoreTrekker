// server.js
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
const port = process.env.port || 5500;
const secretKey = process.env.JWT_SECRET;
const zod = require("zod");

const uservalid = zod
  .string()
  .min(3)
  .max(20)
  .regex(/^[a-zA-Z0-9._]+$/, {
    message:
      "Username can only contain letters, numbers, underscores, and dots.",
  });

const passwordValid = zod
  .string()
  .min(5, { message: "Password must be at least 5 characters long" })
  .max(50, { message: "Password cannot exceed 50 characters" })
//   .regex(/[A-Z]/, {
//     message: "Password must contain at least one uppercase letter",
//   })
//   .regex(/[a-z]/, {
//     message: "Password must contain at least one lowercase letter",
//   })
  .regex(/\d/, { message: "Password must contain at least one number" })
  .regex(/[!@#$%^&*(),.?":{}|<>]/, {
    message: "Password must contain at least one special character",
  })
  .regex(/^\S*$/, { message: "Password cannot contain spaces" });

// Connect to MongoDB
mongoose.connect(process.env.DATABASE_URL);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => {
  console.log("Connected to MongoDB");
});

// Define user schema and model
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
});
const User = mongoose.model("User", userSchema);

// Define task schema and model with `createdAt` field
const taskSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  title: String,
  description: String,
  completed: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }, // Auto-set date and time of task creation
});
const Task = mongoose.model("Task", taskSchema);

// Middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Helper function to verify token
const verifyTokenAndExtractUserInfo = (token) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        reject(err);
      } else {
        resolve(decoded);
      }
    });
  });
};

// Middleware for User Authentication
const authenticateUser = async (req, res, next) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    if (!token) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }
    const { userId } = await verifyTokenAndExtractUserInfo(token);
    req.user = { id: userId };
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: "Unauthorized" });
  }
};

app.post("/Register", async (req, res) => {
  const { username, password } = req.body;

  const passwordValidationResult = passwordValid.safeParse(password);
  if (!passwordValidationResult.success) {
    return res.status(400).json({
      success: false,
      message: passwordValidationResult.error.errors[0].message, // Send the Zod error message to the client
    });
  }

  // Validate the username
  const userValidationResult = uservalid.safeParse(username);
  if (!userValidationResult.success) {
    return res.status(400).json({
      success: false,
      message: userValidationResult.error.errors[0].message, // Send the Zod error message to the client
    });
  }

  try {
    // Check if username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res
        .status(400)
        .json({ success: false, message: "Username already exists" });
    }

    // Hash password and save new user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid username or password" });
    }
    const token = jwt.sign({ userId: user._id }, secretKey);
    res.json({ success: true, token });
  } catch (error) {
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

app.post("/tasks", authenticateUser, async (req, res) => {
  const { title, description } = req.body;
  const userId = req.user.id;
  try {
    const newTask = new Task({ userId, title, description });
    await newTask.save();
    res
      .status(201)
      .json({ success: true, message: "Task created successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

app.get("/tasks", authenticateUser, async (req, res) => {
  const userId = req.user.id;
  try {
    const tasks = await Task.find({ userId });
    res.json(tasks);
  } catch (error) {
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

app.put("/tasks/:taskId/complete", authenticateUser, async (req, res) => {
  const userId = req.user.id;
  const taskId = req.params.taskId;
  try {
    const task = await Task.findOne({ _id: taskId, userId });
    if (!task) {
      return res
        .status(404)
        .json({ success: false, message: "Task not found" });
    }
    task.completed = true;
    await task.save();
    res.json({ success: true, message: "Task marked as completed" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
