const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { validationResult } = require("express-validator");
const sha256 = require("js-sha256").sha256;
require("dotenv").config();

const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;

const validateRequest = (validations) => {
    return async (req, res, next) => {
        await Promise.all(validations.map(validation => validation.run(req)));
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        next();
    };
};

const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "No access token provided" });
    }

    const token = authHeader.split(" ")[1];
    jwt.verify(token, ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid access token" });
        req.user = decoded;
        next();
    });
};

const generateTokens = (user) => {
    const accessToken = jwt.sign({ username: user.username, auth: "user" }, ACCESS_TOKEN_SECRET, { expiresIn: "5m" });
    const refreshToken = jwt.sign({ username: user.username }, REFRESH_TOKEN_SECRET, { expiresIn: "12h" });
    return { accessToken, refreshToken };
};

const refreshToken = (refreshToken, fingerprint) => {
    return new Promise((resolve, reject) => {
        jwt.verify(refreshToken, REFRESH_TOKEN_SECRET, (err, decoded) => {
            if (err) return reject("Invalid refresh token");
            const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded);
            resolve({ accessToken, newRefreshToken });
        });
    });
};

// Utility function to encode HTML entities
const encodeHTML = (str) => {
    return str.replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
};

function validateRefreshToken(token) {
    try {
        return jwt.verify(token, REFRESH_TOKEN_SECRET); // Use the correct secret key
    } catch (err) {
        console.log("Refresh token validation failed:", err.message); // Debugging log
        return null;
    }
}

async function handleRefreshToken(req, res) {
    const { refreshToken } = req.body;
    console.log("Received refresh token:", refreshToken); // Debugging log

    // Validate the refresh token
    const payload = validateRefreshToken(refreshToken);
    if (!payload) {
        console.log("Invalid refresh token"); // Debugging log
        return res.status(401).json({ error: "Invalid refresh token" });
    }

    // Issue a new access token
    const newAccessToken = jwt.sign(
        { username: payload.username },
        ACCESS_TOKEN_SECRET, // Use the correct secret key
        { expiresIn: "5m" }
    );
    console.log("New access token issued:", newAccessToken); // Debugging log
    res.json({ access_token: newAccessToken });
}

module.exports = { 
    validateRequest, 
    verifyToken, 
    generateTokens, 
    refreshToken, 
    encodeHTML, 
    validateRefreshToken, 
    handleRefreshToken
};
