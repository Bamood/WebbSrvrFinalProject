const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { validationResult } = require("express-validator");
const sha256 = require("js-sha256").sha256;
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

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
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid access token" });
        req.user = decoded;
        next();
    });
};

const generateTokens = (user) => {
    const accessToken = jwt.sign({ username: user.username, auth: "user" }, JWT_SECRET, { expiresIn: "10m" });
    const fingerprint = crypto.randomBytes(32).toString('base64');
    const hash = sha256(fingerprint);
    const refreshToken = jwt.sign({ username: user.username, fingerprint: Buffer.from(hash).toString('base64') }, JWT_REFRESH_SECRET, { expiresIn: "12h" });
    return { accessToken, refreshToken, fingerprint };
};

const refreshToken = (refreshToken, fingerprint) => {
    return new Promise((resolve, reject) => {
        jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, decoded) => {
            if (err) return reject("Invalid refresh token");
            if (sha256(fingerprint) !== Buffer.from(decoded.fingerprint, 'base64').toString('utf-8')) {
                return reject("Invalid fingerprint");
            }
            const { accessToken, refreshToken: newRefreshToken, fingerprint: newFingerprint } = generateTokens(decoded);
            resolve({ accessToken, newRefreshToken, newFingerprint });
        });
    });
};

const csrfTokens = new Map(); // Store CSRF tokens temporarily

const generateCsrfToken = (sessionId) => {
    const csrfToken = crypto.randomBytes(32).toString("hex");
    csrfTokens.set(sessionId, csrfToken);
    setTimeout(() => csrfTokens.delete(sessionId), 12 * 60 * 60 * 1000); // Expire after 12 hours
    return csrfToken;
};

const validateCsrfToken = (req, res, next) => {
    const sessionId = req.cookies["fingerprint"];
    const csrfToken = req.headers["x-csrf-token"];
    if (!sessionId || !csrfToken || csrfTokens.get(sessionId) !== csrfToken) {
        return res.status(403).json({ error: "Invalid or missing CSRF token" });
    }
    next();
};

const sanitizeInput = (input) => {
    return input.replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
};

module.exports = { 
    validateRequest, 
    verifyToken, 
    generateTokens, 
    refreshToken, 
    generateCsrfToken, 
    validateCsrfToken, 
    sanitizeInput // Export sanitizeInput
};
