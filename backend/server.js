// ===============================
// Imports
// ===============================

// Database connection
const db = require("./database");

// Libraries
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const express = require("express");
const cors = require("cors");


// ===============================
// App Setup
// ===============================

const app = express();

// Allow frontend and backend to communicate
app.use(cors());

// Allows Express to read JSON request bodies
app.use(express.json());


// ===============================
// JWT Configuration
// ===============================

// Secret used to create and verify JWT tokens
const JWT_SECRET = "my-super-secret-key";


// ===============================
// Health Check Route
// ===============================

// Checks whether the server is running
app.get("/", (req, res) => {
    res.json({
        message: "Auth server is running"
    });
});


// ===============================
// Authentication Middleware
// ===============================

// Checks whether the request contains a valid JWT
function authenticateToken(req, res, next) {

    // Get the Authorization header
    // Example:
    // Authorization: Bearer eyJhbGciOiJIUzI1Ni...
    const authHeader = req.headers["authorization"];

    // Extract only the token
    const token = authHeader && authHeader.split(" ")[1];

    // If no token was provided
    if (!token) {
        return res.status(401).json({
            message: "Access token required"
        });
    }

    // Verify the token
    jwt.verify(token, JWT_SECRET, (err, user) => {

        // Token is invalid or expired
        if (err) {
            return res.status(403).json({
                message: "Invalid or expired token"
            });
        }

        // Store the decoded user information
        // so the next route can access it
        req.user = user;

        // Authentication passed
        next();
    });
}


// ===============================
// Authorization Middleware
// ===============================

// Checks whether the logged-in user is an admin
function requireAdmin(req, res, next) {

    // req.user was added by authenticateToken
    if (req.user.role !== "admin") {
        return res.status(403).json({
            message: "Forbidden: Admin access required"
        });
    }

    // User is an admin
    next();
}


// ===============================
// Login Route
// ===============================

app.post("/login", async (req, res) => {

    // Get email and password from request body
    const { email, password } = req.body;

    // Check that both fields were provided
    if (!email || !password) {
        return res.status(400).json({
            message: "Email and password are required"
        });
    }

   // Find the user in the SQLite database
const user = await new Promise((resolve, reject) => {
    db.get(
        `SELECT id, email, password, role
         FROM users
         WHERE email = ?`,
        [email],
        (err, row) => {
            if (err) {
                reject(err);
            } else {
                resolve(row);
            }
        }
    );
});

    // User with this email doesn't exist
    if (!user) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    // Compare entered password with
    // the stored bcrypt password hash
    const passwordMatch = await bcrypt.compare(
        password,
        user.password
    );

    // Password is incorrect
    if (!passwordMatch) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    // Create a JWT after successful login
    const token = jwt.sign(
        {
            id: user.id,
            email: user.email,
            role: user.role
        },
        JWT_SECRET,
        {
            expiresIn: "1h"
        }
    );

    // Send the token back to the client
    res.json({
        message: "Login successful",
        token: token
    });
});


// ===============================
// Protected Dashboard Route
// ===============================

// Only authenticated users can access this
app.get("/dashboard", authenticateToken, (req, res) => {

    res.json({
        message: "Welcome to your dashboard",
        user: req.user
    });
});


// ===============================
// Admin Route
// ===============================

// User must:
// 1. Have a valid JWT
// 2. Have the admin role
app.get(
    "/admin",
    authenticateToken,
    requireAdmin,
    (req, res) => {

        res.json({
            message: "Welcome to the admin panel",
            user: req.user
        });
    }
);


// ===============================
// Start Server
// ===============================

const PORT = process.env.PORT || 5000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
});