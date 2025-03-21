const express = require("express");
const jwt = require("jsonwebtoken");
const argon2 = require("argon2");
const { body } = require("express-validator");
const db = require("./sqlConnector");
const { validateRequest, verifyToken } = require("./middleware");
const router = express.Router();
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

const generateTokens = (user) => {
    const accessToken = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "1h" });
    const refreshToken = jwt.sign({ username: user.username }, JWT_REFRESH_SECRET, { expiresIn: "7d" });
    return { accessToken, refreshToken };
};

router.post("/register",
    validateRequest([
        body("username").isLength({ min: 3, max: 30 }),
        body("email").isEmail(),
        body("password").isLength({ min: 4 })
    ]),
    async (req, res) => {
        const { username, email, password } = req.body;
        try {
            const hashedPassword = await argon2.hash(password);
            db.query("SELECT * FROM users WHERE username = ? OR email = ?", [username, email], (err, results) => {
                if (err) return res.status(500).json({ error: "Database error" });
                if (results.length > 0) return res.status(400).json({ error: "Username or email already exists" });

                db.query("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    [username, email, hashedPassword], (err) => {
                        if (err) return res.status(500).json({ error: "Database error" });
                        res.status(201).json({ message: "User registered successfully" });
                    });
            });
        } catch (error) {
            res.status(500).json({ error: "Internal server error" });
        }
    });

router.post("/login", async (req, res) => {
    const { username, password } = req.body;
    db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (results.length === 0) return res.status(400).json({ error: "Invalid username or password" });

        const user = results[0];
        try {
            const validPassword = await argon2.verify(user.password.toString(), password);
            if (!validPassword) return res.status(400).json({ error: "Invalid username or password" });

            const { accessToken, refreshToken } = generateTokens(user);
            res.json({ access_token: accessToken, refresh_token: refreshToken });
        } catch (error) {
            res.status(500).json({ error: "Internal server error" });
        }
    });
});

router.post("/refresh-token", (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(401).json({ error: "No refresh token provided" });

    jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid refresh token" });

        const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded);
        res.json({ access_token: accessToken, refresh_token: newRefreshToken });
    });
});

router.delete("/delete", verifyToken, (req, res) => {
    const { username } = req.user;
    db.query("SELECT * FROM users WHERE username = ?", [username], (err, userResults) => {
        if (err || userResults.length === 0) return res.status(404).json({ error: "User not found" });

        db.query("DELETE FROM users WHERE username = ?", [username], (err) => {
            if (err) return res.status(500).json({ error: "Database error" });
            res.json({ message: "User deleted successfully" });
        });
    });
});

module.exports = router;
