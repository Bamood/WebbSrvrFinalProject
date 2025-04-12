const express = require("express");
const argon2 = require("argon2");
const { body } = require("express-validator");
const db = require("./sqlConnector");
const { validateRequest, verifyToken, generateTokens } = require("./tokenManager");
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
    (req, res) => {
        const { username, email, password } = req.body;
        db.query("SELECT * FROM users WHERE username = ? OR email = ?", [username, email], (err, results) => {
            if (err) return res.status(500).json({ error: "Database error" });
            if (results.length > 0) return res.status(400).json({ error: "Username or email already exists" });

            argon2.hash(password).then(hashedPassword => {
                    db.query("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [username, email, hashedPassword], (err) => {
                        if (err) return res.status(500).json({ error: "Database error" });
                        res.status(201).json({ message: "User registered successfully" });
                    });
                }).catch(() => res.status(500).json({ error: "Internal server error" }));
        });
    });

router.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.query("SELECT * FROM users WHERE username = ?", [username], (err, results) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (results.length === 0) return res.status(400).json({ error: "Invalid username or password" });

        const user = results[0];
        argon2.verify(user.password.toString(), password).then(validPassword => {
            if (!validPassword) return res.status(400).json({ error: "Invalid username or password" });

            const { accessToken, refreshToken } = generateTokens(user);
            res.cookie("access_token", accessToken, { httpOnly: true, secure: true, sameSite: "lax", maxAge: 2 * 60 * 1000 }); // Store access token in cookie
            res.cookie("refresh_token", refreshToken, { httpOnly: true, secure: true, sameSite: "lax", maxAge: 12 * 60 * 60 * 1000 }); // Store refresh token in cookie
            res.status(200).json({ message: "Login successful" });
        }).catch(() => res.status(500).json({ error: "Internal server error" }));
    });
});

router.post("/refresh-token", (req, res) => {
    const token = req.cookies.refresh_token;
    if (!token) {
        return res.status(401).json({ error: "No refresh token provided" });
    }

    refreshToken(token)
        .then(({ accessToken, newRefreshToken }) => {
            res.cookie("access_token", accessToken, { httpOnly: true, secure: true, sameSite: "lax", maxAge: 2 * 60 * 1000 }); // Update access token in cookie
            res.cookie("refresh_token", newRefreshToken, { httpOnly: true, secure: true, sameSite: "lax", maxAge: 12 * 60 * 60 * 1000 }); // Update refresh token in cookie
            res.json({ message: "Tokens refreshed successfully" });
        })
        .catch(() => res.status(401).json({ error: "Invalid refresh token" }));
});

router.delete("/delete", verifyToken, (req, res) => {
    const { username } = req.user;

    db.query("DELETE FROM users WHERE username = ?", [username], (err, result) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (result.affectedRows === 0) return res.status(404).json({ error: "User not found" });
        res.json({ message: "User deleted successfully" });
    });
});

router.put("/change-password",
    verifyToken,
    validateRequest([
        body("currentPassword").isLength({ min: 4 }).withMessage("Current password must be at least 4 characters long."),
        body("newPassword").isLength({ min: 4 }).withMessage("New password must be at least 4 characters long.")
    ]),
    (req, res) => {
        const { currentPassword, newPassword } = req.body;
        const { username } = req.user;

        db.query("SELECT * FROM users WHERE username = ?", [username], (err, results) => {
            if (err) return res.status(500).json({ error: "Database error" });
            if (results.length === 0) return res.status(404).json({ error: "User not found" });

            const user = results[0];
            argon2.verify(user.password.toString(), currentPassword).then(validPassword => {
                if (!validPassword) return res.status(400).json({ error: "Current password is incorrect" });

                if (currentPassword === newPassword) {
                    return res.status(400).json({ error: "New password cannot be the same as the current password" });
                }

                argon2.hash(newPassword).then(hashedNewPassword => {
                    db.query("UPDATE users SET password = ? WHERE username = ?", [hashedNewPassword, username], (err) => {
                        if (err) return res.status(500).json({ error: "Database error" });
                        res.clearCookie("refresh_token", { httpOnly: true, secure: true, sameSite: "lax" });
                        res.status(200).json({ message: "Password changed successfully. Please log in again." });
                    });
                }).catch(() => res.status(500).json({ error: "Internal server error" }));
            }).catch(() => res.status(500).json({ error: "Internal server error" }));
        });
    });

router.get("/info", verifyToken, (req, res) => {
    const { username } = req.user;

    db.query("SELECT username, email FROM users WHERE username = ?", [username], (err, results) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (results.length === 0) return res.status(404).json({ error: "User not found" });

        const user = results[0];
        res.json({
            username: (user.username),
            email: (user.email)
        });
    });
});

router.post("/logout", (req, res) => {
    res.clearCookie("access_token", { httpOnly: true, secure: true, sameSite: "lax" }); // Clear access token cookie
    res.clearCookie("refresh_token", { httpOnly: true, secure: true, sameSite: "lax" }); // Clear refresh token cookie
    res.status(200).json({ message: "Logged out successfully" });
});

module.exports = router;
