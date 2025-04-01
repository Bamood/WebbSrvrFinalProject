const express = require("express");
const { body } = require("express-validator");
const db = require("./sqlConnector");
const { validateRequest, verifyToken, encodeHTML } = require("./tokenManager");
const router = express.Router();

router.post("/",
    verifyToken,
    validateRequest([
        body("title").isLength({ min: 1, max: 100 }).trim().withMessage("Title must be between 1 and 100 characters."),
        body("content").isLength({ min: 1 }).trim().withMessage("Content cannot be empty.")
    ]),
    (req, res) => {
        const { title, content } = req.body;
        const { username } = req.user;
        const sanitizedTitle = encodeHTML(title);
        const sanitizedContent = encodeHTML(content);
        db.query("INSERT INTO posts (user, title, content) VALUES (?, ?, ?)",
            [username, sanitizedTitle, sanitizedContent], (err) => {
                if (err) return res.status(500).json({ error: "Database error" });
                res.status(201).json({ message: "Post created successfully" });
            });
    });

router.delete("/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const { username } = req.user;
    db.query("SELECT * FROM posts WHERE id = ?", [id], (err, postResults) => {
        if (err || postResults.length === 0) return res.status(404).json({ error: "Post not found" });

        db.query("DELETE FROM posts WHERE id = ? AND user = ?", [id, username], (err, result) => {
            if (err) return res.status(500).json({ error: "Database error" });
            if (result.affectedRows === 0) return res.status(403).json({ error: "You do not own this post" });
            res.json({ message: "Post deleted successfully" });
        });
    });
});

router.get("/:id", verifyToken, (req, res) => {
    const { id } = req.params;

    db.query("SELECT * FROM posts WHERE id = ?", [id], (err, results) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (results.length === 0) return res.status(404).json({ error: "Post not found" });

        const post = results[0];
        res.json({
            id: post.id,
            user: encodeHTML(post.user),
            title: encodeHTML(post.title),
            content: encodeHTML(post.content),
            created: post.created
        });
    });
});

module.exports = router;
