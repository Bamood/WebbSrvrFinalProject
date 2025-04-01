const express = require("express");
const { body } = require("express-validator");
const db = require("./sqlConnector");
const { validateRequest, verifyToken, encodeHTML } = require("./tokenManager");
const router = express.Router();

router.post("/",
    verifyToken,
    validateRequest([
        body("postId").isInt().withMessage("Post ID must be an integer."),
        body("comment").isLength({ min: 1 }).trim().escape().withMessage("Comment cannot be empty.")
    ]),
    (req, res) => {
        const { postId, comment } = req.body;
        const { username } = req.user;
        const sanitizedComment = encodeHTML(comment);
        db.query("INSERT INTO comments (postId, user, comment) VALUES (?, ?, ?)",
            [postId, username, sanitizedComment], (err) => {
                if (err) return res.status(500).json({ error: "Database error" });
                res.status(201).json({ message: "Comment created successfully" });
            });
    });

router.delete("/:id", verifyToken, (req, res) => {
    const { id } = req.params;
    const { username } = req.user;
    db.query("SELECT * FROM comments WHERE id = ?", [id], (err, commentResults) => {
        if (err || commentResults.length === 0) return res.status(404).json({ error: "Comment not found" });

        db.query("DELETE FROM comments WHERE id = ? AND user = ?", [id, username], (err, result) => {
            if (err) return res.status(500).json({ error: "Database error" });
            if (result.affectedRows === 0) return res.status(403).json({ error: "You do not own this comment" });
            res.json({ message: "Comment deleted successfully" });
        });
    });
});

router.get("/:postId", verifyToken, (req, res) => {
    const { postId } = req.params;

    db.query("SELECT * FROM comments WHERE postId = ?", [postId], (err, results) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (results.length === 0) return res.status(404).json({ error: "No comments found for this post" });

        const encodedComments = results.map(comment => ({
            id: comment.id,
            postId: comment.postId,
            user: encodeHTML(comment.user),
            comment: encodeHTML(comment.comment),
            created_at: comment.created_at
        }));

        res.json(encodedComments);
    });
});

module.exports = router;
