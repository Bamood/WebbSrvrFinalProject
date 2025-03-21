const express = require("express");
const jwt = require("jsonwebtoken");
const argon2 = require("argon2");
const { body, validationResult } = require("express-validator");
const db = require("./sqlConnector");
const router = express.Router();
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

// Function to generate access and refresh tokens
function generateTokens(user) {
    const accessToken = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "1h" });
    const refreshToken = jwt.sign({ username: user.username }, JWT_REFRESH_SECRET, { expiresIn: "7d" });
    return { accessToken, refreshToken };
}

// Registreringsrutt med validering
router.post("/register",
    [
        body("username").isLength({ min: 3, max: 30 }),
        body("email").isEmail(),
        body("password").isLength({ min: 4 })
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, password } = req.body;
        try {
            const hashedPassword = await argon2.hash(password);

            db.query("SELECT * FROM users WHERE username = ? OR email = ?", [username, email], (err, results) => {
                if (err) {
                    console.error("Database query error:", err);
                    return res.status(500).json({ error: "Database error" });
                }
                if (results.length > 0) {
                    return res.status(400).json({ error: "Username or email already exists" });
                }

                db.query("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    [username, email, hashedPassword], (err, results) => {
                        if (err) {
                            console.error("Database insert error:", err);
                            return res.status(500).json({ error: "Database error" });
                        }
                        res.status(201).json({ message: "User registered successfully" });
                    });
            });
        } catch (error) {
            console.error("Error hashing password:", error);
            return res.status(500).json({ error: "Internal server error" });
        }
    });

// Login route to generate access and refresh tokens
router.post("/login", async (req, res) => {
    const { username, password } = req.body;

    db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
        if (err) {
            console.error("Database query error:", err);
            return res.status(500).json({ error: "Database error" });
        }
        if (results.length === 0) {
            return res.status(400).json({ error: "Invalid username or password" });
        }

        const user = results[0];
        const passwordHash = user.password.toString(); // Convert Buffer to string
        console.log("Retrieved password hash:", passwordHash); // Log the password hash for debugging

        try {
            const validPassword = await argon2.verify(passwordHash, password);
            if (!validPassword) {
                return res.status(400).json({ error: "Invalid username or password" });
            }

            const { accessToken, refreshToken } = generateTokens(user);
            res.json({ access_token: accessToken, refresh_token: refreshToken });
        } catch (error) {
            console.error("Error verifying password:", error);
            return res.status(500).json({ error: "Internal server error" });
        }
    });
});

// Route to refresh access token
router.post("/refresh-token", (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(401).json({ error: "No refresh token provided" });
    }

    jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid refresh token" });

        const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded);
        res.json({ access_token: accessToken, refresh_token: newRefreshToken });
    });
});

// Route för att ta bort användare
router.delete("/delete", (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "No access token provided" });
    }

    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid access token" });

        const username = decoded.username;
        db.query("SELECT * FROM users WHERE username = ?", [username], (err, userResults) => {
            if (err || userResults.length === 0) {
                return res.status(404).json({ error: "User not found" });
            }

            db.query("DELETE FROM users WHERE username = ?", [username], (err, result) => {
                if (err) return res.status(500).json({ error: "Database error" });
                res.json({ message: "User deleted successfully" });
            });
        });
    });
});

module.exports = router;
