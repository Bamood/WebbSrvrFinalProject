const express = require("express");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const mysql = require("mysql2");
const argon2 = require("argon2");
const dotenv = require("dotenv");
const { body, validationResult } = require("express-validator");
dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: "*", credentials: true, allowedHeaders: ["Content-Type", "Authorization"] }));

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.error("MySQL anslutningsfel:", err);
    } else {
        console.log("MySQL ansluten!");
    }
});

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

// Function to generate access and refresh tokens
function generateTokens(user) {
    const accessToken = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "1h" });
    const refreshToken = jwt.sign({ username: user.username }, JWT_REFRESH_SECRET, { expiresIn: "7d" });
    return { accessToken, refreshToken };
}

// Registreringsrutt med validering
app.post("/api/users/register",
    [
        body("username").isLength({ min: 3, max: 30 }),
        body("email").isEmail(),
        body("password").isLength({ min: 4 })
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { username, email, password } = req.body;
        try {
            const hashedPassword = await argon2.hash(password);

            db.query("SELECT * FROM users WHERE username = ? OR email = ?", [username, email], (err, results) => {
                if (err) {
                    console.error("Database query error:", err);
                    return res.status(500).json({ error: "Database error" });
                }
                if (results.length > 0) {
                    return res.status(400).json({ error: "Username or email already exists" });
                }

                db.query("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    [username, email, hashedPassword], (err, results) => {
                        if (err) {
                            console.error("Database insert error:", err);
                            return res.status(500).json({ error: "Database error" });
                        }
                        res.status(201).json({ message: "User registered successfully" });
                    });
            });
        } catch (error) {
            console.error("Error hashing password:", error);
            return res.status(500).json({ error: "Internal server error" });
        }
    });

// Login route to generate access and refresh tokens
app.post("/api/users/login", async (req, res) => {
    const { username, password } = req.body;

    db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
        if (err) {
            console.error("Database query error:", err);
            return res.status(500).json({ error: "Database error" });
        }
        if (results.length === 0) {
            return res.status(400).json({ error: "Invalid username or password" });
        }

        const user = results[0];
        const passwordHash = user.password.toString(); // Convert Buffer to string
        console.log("Retrieved password hash:", passwordHash); // Log the password hash for debugging

        try {
            const validPassword = await argon2.verify(passwordHash, password);
            if (!validPassword) {
                return res.status(400).json({ error: "Invalid username or password" });
            }

            const { accessToken, refreshToken } = generateTokens(user);
            res.json({ access_token: accessToken, refresh_token: refreshToken });
        } catch (error) {
            console.error("Error verifying password:", error);
            return res.status(500).json({ error: "Internal server error" });
        }
    });
});

// Route to refresh access token
app.post("/api/users/refresh-token", (req, res) => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        return res.status(401).json({ error: "No refresh token provided" });
    }

    jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid refresh token" });

        const { accessToken, refreshToken: newRefreshToken } = generateTokens(decoded);
        res.json({ access_token: accessToken, refresh_token: newRefreshToken });
    });
});

// CRUD för inlägg
app.post("/api/posts",
    [
        body("title").isLength({ min: 1, max: 100 }).withMessage("Title must be between 1 and 100 characters."),
        body("content").isLength({ min: 1 }).withMessage("Content cannot be empty.")
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ error: "No access token provided" });
        }

        const token = authHeader.split(" ")[1];
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) return res.status(403).json({ error: "Invalid access token" });

            const { title, content } = req.body;
            const username = decoded.username;
            db.query("INSERT INTO posts (user, title, content) VALUES (?, ?, ?)",
                [username, title, content], (err, result) => {
                    if (err) return res.status(500).json({ error: "Database error" });
                    res.status(201).json({ message: "Post created successfully" });
                });
        });
    });

app.delete("/api/posts/:id", (req, res) => {
    const { id } = req.params;
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "No access token provided" });
    }

    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid access token" });

        db.query("SELECT * FROM posts WHERE id = ?", [id], (err, postResults) => {
            if (err || postResults.length === 0) {
                return res.status(404).json({ error: "Post not found" });
            }

            db.query("SELECT * FROM users WHERE username = ?", [decoded.username], (err, userResults) => {
                if (err || userResults.length === 0) {
                    return res.status(403).json({ error: "Invalid user ID" });
                }

                db.query("DELETE FROM posts WHERE id = ? AND user = ?",
                    [id, decoded.username], (err, result) => {
                        if (err) return res.status(500).json({ error: "Database error" });
                        if (result.affectedRows === 0) {
                            return res.status(403).json({ error: "You do not own this post" });
                        }
                        res.json({ message: "Post deleted successfully" });
                    });
            });
        });
    });
});

// CRUD för kommentarer
app.post("/api/comments",
    [
        body("postId").isInt().withMessage("Post ID must be an integer."),
        body("comment").isLength({ min: 1 }).withMessage("Comment cannot be empty.")
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({ error: "No access token provided" });
        }

        const token = authHeader.split(" ")[1];
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) return res.status(403).json({ error: "Invalid access token" });

            const { postId, comment } = req.body;
            const username = decoded.username;
            db.query("INSERT INTO comments (postId, user, comment) VALUES (?, ?, ?)",
                [postId, username, comment], (err, result) => {
                    if (err) return res.status(500).json({ error: "Database error" });
                    res.status(201).json({ message: "Comment created successfully" });
                });
        });
    });

app.delete("/api/comments/:id", (req, res) => {
    const { id } = req.params;
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "No access token provided" });
    }

    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid access token" });

        db.query("SELECT * FROM comments WHERE id = ?", [id], (err, commentResults) => {
            if (err || commentResults.length === 0) {
                return res.status(404).json({ error: "Comment not found" });
            }

            db.query("SELECT * FROM users WHERE username = ?", [decoded.username], (err, userResults) => {
                if (err || userResults.length === 0) {
                    return res.status(403).json({ error: "Invalid user ID" });
                }

                db.query("DELETE FROM comments WHERE id = ? AND user = ?",
                    [id, decoded.username], (err, result) => {
                        if (err) return res.status(500).json({ error: "Database error" });
                        if (result.affectedRows === 0) {
                            return res.status(403).json({ error: "You do not own this comment" });
                        }
                        res.json({ message: "Comment deleted successfully" });
                    });
            });
        });
    });
});

// Route för att ta bort användare
app.delete("/api/users/delete", (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "No access token provided" });
    }

    const token = authHeader.split(" ")[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid access token" });

        const username = decoded.username;
        db.query("SELECT * FROM users WHERE username = ?", [username], (err, userResults) => {
            if (err || userResults.length === 0) {
                return res.status(404).json({ error: "User not found" });
            }

            db.query("DELETE FROM users WHERE username = ?", [username], (err, result) => {
                if (err) return res.status(500).json({ error: "Database error" });
                res.json({ message: "User deleted successfully" });
            });
        });
    });
});

app.listen(8000, (err) => {
    if (err) {
        console.error("Failed to start server:", err);
        process.exit(1);
    }
    console.log("Server running on port 8000");
});