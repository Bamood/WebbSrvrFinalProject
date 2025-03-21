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
app.use(cors({ origin: "*", credentials: true, allowedHeaders: ["Content-Type", "Authorization"] }));

app.use("/api/accounts", accountRoutes);
app.use("/api/posts", postRoutes);
app.use("/api/comments", commentRoutes);

app.listen(PORT, () => console.log(`App listening on port ${PORT}`));
