// server.js
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const cors=require("cors");
const bcrypt=require("bcrypt");
const jwt=require("jsonwebtoken");
const app = express();
const port = process.env.port || 5500;
const secretKey = process.env.JWT_SECRET;

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
    password: String
});
const User = mongoose.model("User", userSchema);

// Define task schema and model
const taskSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    title: String,
    description: String,
    completed: { type: Boolean, default: false }
});
const Task = mongoose.model("Task", taskSchema);

// Middleware
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
// Routes
app.post("/Register", async (req, res) => {
    console.log("Request body:", req.body);
    const { username, password } = req.body;

    try {
        // Check if username already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ success: false, message: "Username already exists" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        // Save user to the database
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        // Redirect to tm.html
        res.json({ success: true });
    
        
    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
   
});

// server.js
const verifyTokenAndExtractUserInfo = (token) => {
    return new Promise((resolve, reject) => {
        console.log("Received token:", token);
        jwt.verify(token, secretKey, (err, decoded) => {
            if (err) {
                console.error("JWT verification error:", err); // Log the error for debugging
                reject(err); // Reject the promise with the error
            } else {
                console.log("Decoded token payload:", decoded);
                resolve(decoded); // Resolve the promise with the decoded token payload
            }
        });
    });
};


// Middleware for User Authentication
const authenticateUser = async (req, res, next) => {
    try {
        // Extract token or session from request (e.g., from headers, cookies, etc.)
        const token = req.headers.authorization.split(' ')[1];
        
        // Your authentication logic here (e.g., verify token, check session, etc.)
        if (!token) {
            return res.status(401).json({ success: false, message: "Unauthorized" });
        }
        const { userId } = await verifyTokenAndExtractUserInfo(token);
        // Assuming you have a function to verify the token and extract user information
       // const user = await verifyTokenAndExtractUserInfo(token);
       req.user = { id: userId };
        // Attach user information to the request object for use in route handlers
       // req.user = user;
        
        // Move to the next middleware or route handler
        next();
    } catch (error) {
        console.error("Error:", error);
        res.status(401).json({ success: false, message: "Unauthorized" });
    }
};

app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        // Find the user in the database by username
        const user = await User.findOne({ username });

        // If user not found or password doesn't match, return error
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ success: false, message: "Invalid username or password" });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, secretKey);
        return res.json({ success: true, token });
    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

// Add a route to handle login requests

// function generateRandomString(length) {
//     const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+{}[]|\\;:\'",./<>?`~';
//     let result = '';
//     const charactersLength = characters.length;
//     for (let i = 0; i < length; i++) {
//         result += characters.charAt(Math.floor(Math.random() * charactersLength));
//     }
//     return result;
// }

// const secretKey = generateRandomString(64); // Generate a 64-character random string
// console.log(secretKey);





// Apply Authentication Middleware to Routes
app.post("/tasks", authenticateUser, async (req, res) => {
    const { title, description } = req.body;
    const userId = req.user.id;

    try {
        const newTask = new Task({ userId, title, description });
        await newTask.save();
        res.status(201).json({ success: true, message: "Task created successfully" });
    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});

app.get("/tasks", authenticateUser, async (req, res) => {
    const userId = req.user.id;
    console.log("Authenticated user ID:", userId);
    try {
        const tasks = await Task.find({ userId });
        console.log("Retrieved tasks:", tasks);
        res.json(tasks);
    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});
// Add a route to handle marking a task as done
app.put("/tasks/:taskId/complete", authenticateUser, async (req, res) => {
    const userId = req.user.id;
    const taskId = req.params.taskId;

    try {
        // Check if the task exists and belongs to the authenticated user
        const task = await Task.findOne({ _id: taskId, userId });

        if (!task) {
            return res.status(404).json({ success: false, message: "Task not found" });
        }

        // Update the task's completion status to true
        task.completed = true;
        await task.save();

        res.json({ success: true, message: "Task marked as completed" });
    } catch (error) {
        console.error("Error:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
});


console.log(secretKey);


// Start server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
