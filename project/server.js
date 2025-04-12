const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const accountRoutes = require("./api/accounts");
const postRoutes = require("./api/posts");
const commentRoutes = require("./api/comments");

const app = express();
const PORT = 8000;

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ["http://127.0.0.1:5500", "http://localhost:8000"], 
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
    exposedHeaders: ["Set-Cookie"]
}));

app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", 
        "default-src 'self'; " +
        "script-src 'self' 'unsafe-inline'; " +
        "style-src 'self'; " +
        "img-src 'self'; " +
        "connect-src 'self' http://localhost:8000; " +
        "frame-ancestors 'none';");
    next();
});

app.use("/api/accounts", accountRoutes);
app.use("/api/posts", postRoutes);
app.use("/api/comments", commentRoutes);

app.listen(PORT, () => console.log(`App listening on port ${PORT}`));
