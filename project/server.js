const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const csrf = require("csurf"); // Import CSRF middleware directly
const accountRoutes = require("./api/accounts");
const postRoutes = require("./api/posts");
const commentRoutes = require("./api/comments");

const app = express();
const PORT = 8000;

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ["http://localhost:8000", "http://127.0.0.1:5500"], // Allow both origins
    credentials: true, // Allow cookies
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"] // Include X-CSRF-Token
}));

// Add debugging for CSRF validation
app.use((req, res, next) => {
    if (req.headers["x-csrf-token"]) {
        console.log("Received CSRF token:", req.headers["x-csrf-token"]); // Debugging log
    } else {
        console.warn("No CSRF token received in request headers"); // Debugging log
    }
    next();
});

// Initialize CSRF protection middleware
const csrfProtection = csrf({ cookie: true });

// Apply CSRF middleware to all API routes except login and refresh-token
app.use("/api", (req, res, next) => {
    if (req.path === "/accounts/login" || req.path === "/accounts/refresh-token") {
        return next(); // Skip CSRF protection for these routes
    }
    csrfProtection(req, res, next);
});

// Endpoint to fetch CSRF token
app.get("/csrf-token", csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Add debugging for refresh token validation
app.post("/api/accounts/refresh-token", (req, res, next) => {
    const refreshToken = req.cookies.refresh_token;
    console.log("Received refresh token:", refreshToken); // Debugging log
    if (!refreshToken) {
        console.error("No refresh token provided"); // Debugging log
        return res.status(401).json({ error: "No refresh token provided" });
    }
    next();
});

// Add debugging for CSRF validation failures
app.use((err, req, res, next) => {
    if (err.code === "EBADCSRFTOKEN") {
        console.error("CSRF validation failed:", err.message); // Debugging log
        return res.status(403).json({ error: "Invalid CSRF token" });
    }
    next(err);
});

// Add Content Security Policy (CSP) headers
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", 
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self'; " +
        "img-src 'self'; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none';");
    next();
});

app.use("/api/accounts", accountRoutes);
app.use("/api/posts", postRoutes);
app.use("/api/comments", commentRoutes);

app.listen(PORT, () => console.log(`App listening on port ${PORT}`));

module.exports = { 
    csrfProtection
};
