const express = require("express");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const db = require("./sqlConnector");
const router = express.Router();
require("dotenv").config();

const JWT_SECRET = process.env.JWT_SECRET;

// CRUD för kommentarer
router.post("/",
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

router.delete("/:id", (req, res) => {
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

module.exports = router;
