const express = require("express");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const db = require("./sqlConnector");
const router = express.Router();
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET;

// CRUD för inlägg
router.post("/",
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

router.delete("/:id", (req, res) => {
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

module.exports = router;
