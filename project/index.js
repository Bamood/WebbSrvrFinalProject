const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: "http://127.0.0.1:5500", credentials: true, allowedHeaders: ["Content-Type", "Authorization"] }));

const users = { testuser: "password123" };
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "refreshsecretkey";
const refreshTokens = {};

app.post("/api/tokens/login", (req, res) => {
    const { username, password } = req.body;
    if (users[username] !== password) {
        return res.status(401).json({ error: "Invalid credentials" });
    }
    
    const fingerprint = crypto.randomBytes(32).toString("base64");
    const fingerprintHash = crypto.createHash("sha256").update(fingerprint).digest("base64");
    
    const accessToken = jwt.sign({ username, auth: "user" }, JWT_SECRET, { expiresIn: "10m" });
    const refreshToken = jwt.sign({ username, fingerprint: fingerprintHash }, REFRESH_SECRET, { expiresIn: "12h" });
    refreshTokens[refreshToken] = username;
    
    res.cookie("fingerprint", fingerprint, { httpOnly: true, maxAge: 12 * 60 * 60 * 1000 });
    res.json({ access_token: accessToken, refresh_token: refreshToken });
});

app.post("/api/tokens/refresh", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(403).json({ error: "No refresh token provided" });
    }
    const token = authHeader.split(" ")[1];
    if (!refreshTokens[token]) {
        return res.status(403).json({ error: "Invalid refresh token" });
    }
    
    jwt.verify(token, REFRESH_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        const fingerprint = req.cookies["fingerprint"];
        if (!fingerprint || crypto.createHash("sha256").update(fingerprint).digest("base64") !== decoded.fingerprint) {
            return res.status(403).json({ error: "Fingerprint mismatch" });
        }
        
        const newAccessToken = jwt.sign({ username: decoded.username, auth: "user" }, JWT_SECRET, { expiresIn: "10m" });
        res.json({ access_token: newAccessToken });
    });
});

app.get("/api/user", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "No access token provided" });
    }
    
    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid access token" });
        res.json({ username: decoded.username });
    });
});

app.listen(8000, () => console.log("Server running on port 8000"));
