const express = require("express");
const argon2 = require("argon2");
const { body } = require("express-validator");
const db = require("./sqlConnector");
const { validateRequest, verifyToken, generateTokens, handleRefreshToken, encodeHTML } = require("./tokenManager");
const router = express.Router();
require("dotenv").config();

router.post("/register",
    validateRequest([
        body("username").isLength({ min: 3, max: 30 }).trim().escape(),
        body("email")
            .isEmail().withMessage("Invalid email format")
            .matches(/@(?:gmail\.com|yahoo\.com|outlook\.com|hotmail\.com|icloud\.com|aol\.com|protonmail\.com|zoho\.com|yandex\.com|mail\.com)$/)
            .withMessage("Invalid email domain. Allowed domains: gmail.com, yahoo.com, outlook.com, hotmail.com, icloud.com, aol.com, protonmail.com, zoho.com, yandex.com, mail.com")
            .normalizeEmail(),
        body("password").isLength({ min: 4 }).escape()
    ]),
    async (req, res) => {
        const { username, email, password } = req.body;
        try {
            db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
                if (err) return res.status(500).json({ error: "Database error" });
                if (results.length > 0) return res.status(400).json({ error: "Username already exists" });

                const hashedPassword = await argon2.hash(password);
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
        if (err) {
            console.error("Database error during login:", err); // Debugging log
            return res.status(500).json({ error: "Database error" });
        }
        if (results.length === 0) {
            console.warn("Invalid username or password for username:", username); // Debugging log
            return res.status(400).json({ error: "Invalid username or password" });
        }

        const user = results[0];
        try {
            const validPassword = await argon2.verify(user.password.toString(), password);
            if (!validPassword) {
                console.warn("Invalid password for username:", username); // Debugging log
                return res.status(400).json({ error: "Invalid username or password" });
            }

            const { accessToken, refreshToken } = generateTokens(user);
            res.cookie("refresh_token", refreshToken, { httpOnly: true, secure: true, sameSite: "strict", maxAge: 12 * 60 * 60 * 1000 })
                .status(200)
                .json({ access_token: accessToken });
        } catch (error) {
            console.error("Error during password verification:", error); // Debugging log
            res.status(500).json({ error: "Internal server error" });
        }
    });
});

router.post("/refresh-token", async (req, res) => {
    const refreshToken = req.cookies.refresh_token;
    if (!refreshToken) return res.status(401).json({ error: "No refresh token provided" });

    try {
        const { accessToken, newRefreshToken } = await refreshToken(refreshToken);
        res.cookie("refresh_token", newRefreshToken, { httpOnly: true, secure: true, sameSite: "strict", maxAge: 12 * 60 * 60 * 1000 });
        res.json({ access_token: accessToken });
    } catch (error) {
        res.status(401).json({ error });
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

                const isSamePassword = await argon2.verify(user.password.toString(), newPassword);
                if (isSamePassword) return res.status(400).json({ error: "New password cannot be the same as the current password" });

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

router.post("/logout", (req, res) => {
        res.clearCookie("fingerprint", { httpOnly: true, secure: true, sameSite: "strict" });
    res.status(200).json({ message: "Logged out successfully" });
});

module.exports = router;
