const express = require("express");
const argon2 = require("argon2");
const { body } = require("express-validator");
const db = require("./sqlConnector");
const { validateRequest, verifyToken, generateTokens, refreshToken, encodeHTML } = require("./tokenManager");
const router = express.Router();
require("dotenv").config();

router.post("/register",
    validateRequest([
        body("username").isLength({ min: 3, max: 30 }).trim().escape(),
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
            if (!validPassword) {
                return res.status(400).json({ error: "Invalid username or password" }); // Error message for wrong password
            }

            const { accessToken, refreshToken, fingerprint } = generateTokens(user);
            res.cookie("fingerprint", fingerprint, { httpOnly: true, secure: true, maxAge: 12 * 60 * 60 * 1000, sameSite: "lax" })
                .status(200)
                .json({ access_token: accessToken, refresh_token: refreshToken });
        } catch (error) {
            res.status(500).json({ error: "Internal server error" });
        }
    });
});

router.post("/refresh-token", (req, res) => {
    const { refreshToken } = req.body;

    // Validate the refresh token
    if (!refreshToken || refreshToken !== "expected_refresh_token") {
        return res.status(401).json({ error: "Invalid refresh token" });
    }

    // Issue a new access token
    const newAccessToken = "new_access_token"; // Replace with actual token generation logic
    res.json({ access_token: newAccessToken });
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
        body("currentPassword").isLength({ min: 4 }).escape(),
        body("newPassword").isLength({ min: 4 }).escape()
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

                    // Clear cookies to log the user out
                    res.clearCookie("fingerprint", { httpOnly: true, secure: true, sameSite: "lax" });
                    res.status(200).json({ message: "Password changed successfully. Please log in again." });
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
        res.json({
            username: encodeHTML(user.username),
            email: encodeHTML(user.email)
        });
    });
});

module.exports = router;
