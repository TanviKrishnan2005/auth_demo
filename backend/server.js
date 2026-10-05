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
require("dotenv").config();
const OpenAI = require("openai");


// ===============================
// AI Client
// ===============================

const client = new OpenAI({
    apiKey: process.env.GROQ_API_KEY,
    baseURL: "https://api.groq.com/openai/v1"
});


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

const JWT_SECRET = "my-super-secret-key";


// ===============================
// Health Check Route
// ===============================

app.get("/", (req, res) => {
    res.json({
        message: "Auth server is running"
    });
});


// ===============================
// Authentication Middleware
// ===============================

function authenticateToken(req, res, next) {

    const authHeader = req.headers["authorization"];

    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "Access token required"
        });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {

        if (err) {
            return res.status(403).json({
                message: "Invalid or expired token"
            });
        }

        req.user = user;

        next();
    });
}


// ===============================
// Authorization Middleware
// ===============================

function requireAdmin(req, res, next) {

    if (req.user.role !== "admin") {
        return res.status(403).json({
            message: "Forbidden: Admin access required"
        });
    }

    next();
}


// ===============================
// Login Route
// ===============================

app.post("/login", async (req, res) => {

    const { email, password } = req.body;

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

    if (!user) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    // Compare entered password with stored hash
    const passwordMatch = await bcrypt.compare(
        password,
        user.password
    );

    if (!passwordMatch) {
        return res.status(401).json({
            message: "Invalid email or password"
        });
    }

    // Create JWT
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

    res.json({
        message: "Login successful",
        token: token
    });
});


// ===============================
// Protected Dashboard Route
// ===============================

app.get("/dashboard", authenticateToken, (req, res) => {

    res.json({
        message: "Welcome to your dashboard",
        user: req.user
    });
});


// ===============================
// Admin Route
// ===============================

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
// AI Support Decision Route
// ===============================

app.post("/support", authenticateToken, async (req, res) => {

    const { message } = req.body;

    if (!message) {
        return res.status(400).json({
            message: "Support message is required"
        });
    }

    try {

        const response = await client.chat.completions.create({
            model: "openai/gpt-oss-20b",

            messages: [
                {
                    role: "system",
                    content:
                        "Classify the customer message as exactly one of: refund, technical, general. Return only the category."
                },
                {
                    role: "user",
                    content: message
                }
            ],

            temperature: 0
        });

        const decision = response.choices[0].message.content
            .trim()
            .toLowerCase();

        if (decision === "refund") {

            return res.json({
                decision: "refund",
                action: "Route to refund support"
            });
        }

        if (decision === "technical") {

            return res.json({
                decision: "technical",
                action: "Route to technical support"
            });
        }

        return res.json({
            decision: "general",
            action: "Route to general support"
        });

    } catch (error) {

        console.error(error);

        return res.status(500).json({
            message: "AI decision failed"
        });
    }
});


// ===============================
// Start Server
// ===============================

const PORT = process.env.PORT || 5000;

app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
});