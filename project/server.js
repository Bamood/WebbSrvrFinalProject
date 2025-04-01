const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const csurf = require("csurf");
const accountRoutes = require("./api/accounts");
const postRoutes = require("./api/posts");
const commentRoutes = require("./api/comments");

const app = express();
const PORT = 8000;

// Ensure cookieParser is applied before csurf
app.use(express.json());
app.use(cookieParser());

// Configure CORS before CSRF
app.use(cors({
    origin: ["http://localhost:8000", "http://127.0.0.1:5500"],
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"]
}));

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

// Create the CSRF protection middleware
const csrfProtection = csurf({
    cookie: {
        httpOnly: true,
        secure: true, // Use secure cookies in production
        sameSite: "lax" // Use lax to allow cookies in navigation
    }
});

// Add a route to get CSRF token - must come before protected routes
app.get("/api/csrf-token", csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Apply CSRF middleware selectively to routes that modify data
app.use("/api/accounts", accountRoutes); // CSRF protection is applied inside accountRoutes
app.use("/api/posts", csrfProtection, postRoutes);
app.use("/api/comments", csrfProtection, commentRoutes);


app.listen(PORT, () => console.log(`App listening on port ${PORT}`));
