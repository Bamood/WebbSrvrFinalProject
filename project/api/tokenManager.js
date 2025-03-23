const jwt = require("jsonwebtoken");
const { validationResult } = require("express-validator");
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
    const accessToken = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "1h" });
    const refreshToken = jwt.sign({ username: user.username }, JWT_REFRESH_SECRET, { expiresIn: "7d" });
    return { accessToken, refreshToken };
};

const refreshToken = (refreshToken) => {
    return new Promise((resolve, reject) => {
        jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, decoded) => {
            if (err) return reject("Invalid refresh token");
            const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded);
            resolve({ accessToken, newRefreshToken });
        });
    });
};

module.exports = { validateRequest, verifyToken, generateTokens, refreshToken };
