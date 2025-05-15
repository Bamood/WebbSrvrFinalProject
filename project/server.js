const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const csrf = require("csurf");
const path = require("path");
const accountRoutes = require("./api/accounts");
const postRoutes = require("./api/posts");
const commentRoutes = require("./api/comments");

const app = express();
const PORT = 8000;

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: ["http://localhost:8000"], 
    credentials: true, 
    allowedHeaders: ["Content-Type", "Authorization", "CSRF-Token"]
}));


const csrfProtection = csrf({ 
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',  
        sameSite: 'strict',
        maxAge: 3600 
    }
});

app.use('/api/accounts/login', csrfProtection);
app.use('/api/accounts/register', csrfProtection);
app.use('/api/accounts/change-password', csrfProtection);
app.use('/api/accounts/delete', csrfProtection);
app.use('/api/posts', csrfProtection);
app.use('/api/comments', csrfProtection);

app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});



app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", 
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self'; " +
        "img-src 'self'; " +
        "frame-ancestors 'none';");
    next();
});

app.use(express.static(path.join(__dirname, "../project")));
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "../project/login.html"));
});

app.use("/api/accounts", accountRoutes);
app.use("/api/posts", postRoutes);
app.use("/api/comments", commentRoutes);

app.listen(PORT, () => console.log(`App listening on port ${PORT}`));
