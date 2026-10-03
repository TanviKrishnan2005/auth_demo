const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");

const db = new sqlite3.Database("./auth.db", (err) => {
    if (err) {
        console.error("Database connection failed:", err.message);
    } else {
        console.log("Connected to SQLite database");
    }
});

db.run(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
`, (err) => {
    if (err) {
        console.error("Table creation failed:", err.message);
    } else {
        console.log("Users table ready");
    }
});

const tanviPassword = bcrypt.hashSync("123456", 10);
const adminPassword = bcrypt.hashSync("admin123", 10);

db.run(
    `INSERT OR IGNORE INTO users (email, password, role)
     VALUES (?, ?, ?)`,
    ["tanvi@test.com", tanviPassword, "user"]
);

db.run(
    `INSERT OR IGNORE INTO users (email, password, role)
     VALUES (?, ?, ?)`,
    ["admin@test.com", adminPassword, "admin"]
);

module.exports = db;