const express = require("express");
const { body } = require("express-validator");
const db = require("./sqlConnector");
const { validateRequest, verifyToken } = require("./tokenManager"); // Removed encodeHTML
const router = express.Router();

router.post("/",
    verifyToken,
    validateRequest([
        body("postId").isInt().withMessage("Post ID must be a valid integer."),
        body("comment").isLength({ min: 1 }).trim().escape().withMessage("Comment cannot be empty.")
    ]),
    (req, res) => {
        const { postId, comment } = req.body;
        const { username } = req.user;

        // Check if the postId exists in the posts table
        db.query("SELECT id FROM posts WHERE id = ?", [postId], (err, results) => {
            if (err) return res.status(500).json({ error: "Database error" });
            if (results.length === 0) return res.status(404).json({ error: "Post not found" });

            // Insert the comment if the post exists
            db.query("INSERT INTO comments (postId, user, comment) VALUES (?, ?, ?)", [postId, username, comment], (err) => {
                if (err) return res.status(500).json({ error: "Database error" });
                res.status(201).json({ message: "Comment created successfully" });
            });
        });
    });

router.delete("/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const { username } = req.user;

    // Check if the comment exists and is owned by the user
    db.query("SELECT * FROM comments WHERE id = ? AND user = ?", [id, username], (err, results) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (results.length === 0) return res.status(404).json({ error: "Comment not found or you do not own this comment" });

        // Delete the comment
        db.query("DELETE FROM comments WHERE id = ?", [id], (err) => {
            if (err) return res.status(500).json({ error: "Database error" });
            res.json({ message: "Comment deleted successfully" });
        });
    });
});

router.get("/:postId", verifyToken, (req, res) => {
    const { postId } = req.params;

    db.query("SELECT * FROM comments WHERE postId = ?", [postId], (err, results) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (results.length === 0) return res.status(404).json({ error: "No comments found for this post" });

        res.json(results.map(comment => ({
            id: comment.id,
            postId: comment.postId,
            user: comment.user,
            comment: comment.comment,
            created_at: comment.created_at
        })));
    });
});

module.exports = router;
