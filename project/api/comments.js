const express = require("express");
const { body } = require("express-validator");
const db = require("./sqlConnector");
const { validateRequest, verifyToken } = require("./middleware");
const router = express.Router();

router.post("/",
    verifyToken,
    validateRequest([
        body("postId").isInt().withMessage("Post ID must be an integer."),
        body("comment").isLength({ min: 1 }).withMessage("Comment cannot be empty.")
    ]),
    (req, res) => {
        const { postId, comment } = req.body;
        const { username } = req.user;
        db.query("INSERT INTO comments (postId, user, comment) VALUES (?, ?, ?)",
            [postId, username, comment], (err) => {
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

module.exports = router;
