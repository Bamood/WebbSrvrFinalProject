const express = require("express");
const argon2 = require("argon2");
const { body } = require("express-validator");
const db = require("./sqlConnector");
const { validateRequest, verifyToken, generateTokens } = require("./tokenManager");
const router = express.Router();
const jwt = require('jsonwebtoken');
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
            
            res.cookie("access_token", accessToken, {
                httpOnly: true,
                secure: false,
                sameSite: 'lax',
                path: '/',
                maxAge: 2 * 60 * 1000 // 2 minutes
            });

            res.cookie("refresh_token", refreshToken, {
                httpOnly: true,
                secure: false,
                sameSite: 'lax',
                path: '/',
                maxAge: 12 * 60 * 60 * 1000 // 12 hours
            });
            
            res.status(200).json({ 
                message: "Login successful",
                username: user.username 
            });
        }).catch(() => res.status(500).json({ error: "Internal server error" }));
    });
});

router.post("/refresh-token", (req, res) => {
    console.log("Received refresh token request");
    console.log("All cookies:", req.cookies);
    
    const token = req.cookies.refresh_token;
    if (!token) {
        console.error("No refresh token in cookies");
        return res.status(401).json({ error: "No refresh token provided" });
    }

    try {
        const decoded = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
        console.log("Token verified:", decoded);

        const { accessToken, refreshToken: newRefreshToken } = generateTokens({ username: decoded.username });
        
        res.cookie("access_token", accessToken, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            path: '/',
            maxAge: 2 * 60 * 1000 // 2 minutes
        });
        
        res.cookie("refresh_token", newRefreshToken, {
            httpOnly: true,
            secure: false,
            sameSite: 'lax',
            path: '/',
            maxAge: 12 * 60 * 60 * 1000
        });
        
        return res.json({ access_token: accessToken });
    } catch (err) {
        console.error("Token verification failed:", err.message);
        return res.status(401).json({ error: "Invalid refresh token" });
    }
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
                        res.clearCookie("refresh_token", { httpOnly: false, secure: false, sameSite: "lax" });
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
    // Clear both tokens
    res.clearCookie("access_token", {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/'
    });
    res.clearCookie("refresh_token", {
        httpOnly: true,
        secure: false,
        sameSite: 'lax',
        path: '/'
    });
    res.status(200).json({ message: "Logged out successfully" });
});

router.get("/check-auth", (req, res) => {
    const token = req.cookies.access_token;
    if (!token) {
        return res.status(200).json({ authenticated: false });
    }

    try {
        const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        return res.json({ 
            authenticated: true,
            username: decoded.username
        });
    } catch (err) {
        // Try to refresh the token if access token is expired
        const refreshToken = req.cookies.refresh_token;
        if (refreshToken) {
            try {
                const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
                const { accessToken } = generateTokens({ username: decoded.username });
                
                res.cookie("access_token", accessToken, {
                    httpOnly: true,
                    secure: false,
                    sameSite: 'lax',
                    path: '/',
                    maxAge: 2 * 60 * 1000
                });

                return res.json({ 
                    authenticated: true,
                    username: decoded.username
                });
            } catch (refreshErr) {
                // Both tokens are invalid
                return res.status(200).json({ authenticated: false });
            }
        }
        return res.status(200).json({ authenticated: false });
    }
});

module.exports = router;
