require("dotenv").config();
const mysql = require("mysql2");

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 30000
});

db.connect(err => {
    if (err) {
        console.error("MySQL connection error:", err);
    } else {
        console.log("MySQL connected!");
    }
});

module.exports = db;
