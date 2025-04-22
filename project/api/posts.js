const express = require("express");
const { body } = require("express-validator");
const db = require("./sqlConnector");
const { validateRequest, verifyToken } = require("./tokenManager");
const router = express.Router();

router.post("/",
    verifyToken,
    validateRequest([
        body("title").isLength({ min: 1, max: 100 }).trim().escape().withMessage("Title must have a maximum of 100 characters."),
        body("content").isLength({ min: 1 }).trim().escape().withMessage("Content cannot be empty.")
    ]),
    (req, res) => {
        const { title, content } = req.body;
        const { username } = req.user;

        db.query("INSERT INTO posts (user, title, content) VALUES (?, ?, ?)", [username, title, content], (err) => {
            if (err) {
                if (err.code === "ER_DATA_TOO_LONG") {
                    return res.status(400).json({ error: "Title exceeds the maximum length of 100 characters." });
                }
                return res.status(500).json({ error: "Database error" });
            }
            res.status(201).json({ message: "Post created successfully" });
        });
    });

router.delete("/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const { username } = req.user;

    db.query("DELETE FROM posts WHERE id = ? AND user = ?", [id, username], (err, result) => {
        if (err) {
            return res.status(500).json({ error: "Database error" });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Post not found or you do not own this post" });
        }
        res.json({ message: "Post deleted successfully" });
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
            user: post.user,
            title: post.title,
            content: post.content,
            created: post.created
        });
    });
});

router.get("/", verifyToken, (req, res) => {
    db.query("SELECT id, title, content, user, created FROM posts", (err, results) => {
        if (err) {
            return res.status(500).json({ error: "Database error" });
        }
        res.json(results);
    });
});

module.exports = router;
