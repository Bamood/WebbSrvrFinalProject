const express = require("express");
const argon2 = require("argon2");
const { body } = require("express-validator");
const db = require("./sqlConnector");
const { validateRequest, verifyToken, generateTokens, refreshToken } = require("./tokenManager");
const router = express.Router();
require("dotenv").config();

router.post("/register",
    validateRequest([
        body("username").isLength({ min: 3, max: 30 }).escape(),
        body("email").isEmail().normalizeEmail(),
        body("password").isLength({ min: 4 }).escape()
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

            const { accessToken, refreshToken, fingerprint } = generateTokens(user);
            res.cookie("fingerprint", fingerprint, { httpOnly: true, maxAge: 12 * 60 * 60 * 1000, sameSite: "lax" })
                .status(200)
                .json({ access_token: accessToken, refresh_token: refreshToken });
        } catch (error) {
            res.status(500).json({ error: "Internal server error" });
        }
    });
});

router.post("/refresh-token", async (req, res) => {
    const { refreshToken: token } = req.body;
    const fingerprint = req.cookies["fingerprint"];
    if (!token) return res.status(401).json({ error: "No refresh token provided" });
    if (!fingerprint) return res.status(401).json({ error: "No fingerprint provided" });

    try {
        const { accessToken, newRefreshToken, newFingerprint } = await refreshToken(token, fingerprint);
        res.cookie("fingerprint", newFingerprint, { httpOnly: true, maxAge: 12 * 60 * 60 * 1000, sameSite: "lax" });
        res.json({ access_token: accessToken, refresh_token: newRefreshToken });
    } catch (error) {
        res.status(403).json({ error });
    }
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

router.put("/change-password",
    verifyToken,
    validateRequest([
        body("currentPassword").isLength({ min: 4 }),
        body("newPassword").isLength({ min: 4 })
    ]),
    async (req, res) => {
        const { currentPassword, newPassword } = req.body;
        const { username } = req.user;

        db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
            if (err) return res.status(500).json({ error: "Database error" });
            if (results.length === 0) return res.status(404).json({ error: "User not found" });

            const user = results[0];
            try {
                const validPassword = await argon2.verify(user.password.toString(), currentPassword);
                if (!validPassword) return res.status(400).json({ error: "Current password is incorrect" });

                const hashedNewPassword = await argon2.hash(newPassword);
                db.query("UPDATE users SET password = ? WHERE username = ?", [hashedNewPassword, username], (err) => {
                    if (err) return res.status(500).json({ error: "Database error" });
                    res.json({ message: "Password changed successfully" });
                });
            } catch (error) {
                res.status(500).json({ error: "Internal server error" });
            }
        });
    });

router.get("/info", verifyToken, (req, res) => {
    const { username } = req.user;

    db.query("SELECT username, email FROM users WHERE username = ?", [username], (err, results) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (results.length === 0) return res.status(404).json({ error: "User not found" });

        const user = results[0];
        res.json({ username: user.username, email: user.email });
    });
});

module.exports = router;
