const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const csrf = require("csurf");
const accountRoutes = require("./api/accounts");
const postRoutes = require("./api/posts");
const commentRoutes = require("./api/comments");
const { generateTokens } = require("./api/tokenManager"); // Import generateTokens

const app = express();
const PORT = 8000;

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ["http://localhost:8000"], // Only allow trusted origins
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "CSRF-Token"], // Allow CSRF-Token header
}));

app.use((req, res, next) => {
    const nonce = crypto.randomBytes(16).toString("base64"); // Generate a unique nonce
    res.locals.nonce = nonce; // Store the nonce for use in templates
    res.setHeader("Content-Security-Policy", 
        `default-src 'self'; ` +
        `script-src 'self' 'nonce-${nonce}'; ` + // Apply the nonce to inline scripts
        `style-src 'self'; ` +
        `img-src 'self' data:; ` + // Allow only self-hosted and data URIs for images
        `frame-ancestors 'none';`);
    next();
});

// Enable CSRF protection
const csrfProtection = csrf({ cookie: true });

// Exclude specific routes from CSRF protection
app.use((req, res, next) => {
    const csrfExcludedRoutes = ["/api/accounts/login"];
    if (csrfExcludedRoutes.includes(req.path)) {
        return next();
    }
    csrfProtection(req, res, next);
});

// Validate HTTP Methods
app.use((req, res, next) => {
    if (["POST", "PUT", "DELETE"].includes(req.method) && !req.headers["csrf-token"]) {
        return res.status(403).json({ error: "CSRF token missing or invalid" });
    }
    next();
});

// Avoid JSON CSRF
app.use((req, res, next) => {
    if (["POST", "PUT", "DELETE"].includes(req.method) && req.headers["content-type"] !== "application/json") {
        return res.status(400).json({ error: "Invalid Content-Type" });
    }
    next();
});

// Add a route to send the CSRF token to the frontend
app.get("/api/csrf-token", csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

app.post("/api/accounts/login", (req, res) => {
    const { accessToken, refreshToken } = generateTokens(req.body); // Use generateTokens
    res.cookie("refresh_token", refreshToken, {
        httpOnly: true,
        secure: true, // Only send over HTTPS
        sameSite: "Strict", // Prevent cross-origin requests
    });
    res.json({ access_token: accessToken });
});

// Serve static files (frontend)
app.use(express.static(path.join(__dirname, "../project")));
app.use("/api/comments", commentRoutes);
app.use("/api/posts", postRoutes);
app.use("/api/accounts", accountRoutes);

app.use((err, req, res, next) => {
    if (err.code === "EBADCSRFTOKEN") {
        return res.status(403).json({ error: "Invalid CSRF token" });
    }
    next(err);
});

app.listen(PORT, () => console.log(`App listening on port ${PORT}`));