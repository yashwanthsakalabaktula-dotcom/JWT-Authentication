
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();

app.use(cors());
app.use(express.json());

const SECRET_KEY = "my_secret_key";

// Temporary user storage
const users = [];

// Registration
app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).send("Enter username and password");
    }

    const existingUser = users.find(
        user => user.username === username
    );

    if (existingUser) {
        return res.status(400).send("Username already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({
        username,
        password: hashedPassword
    });

    res.send("Registration Successful!");
});

// Login
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(
        user => user.username === username
    );

    if (!user) {
        return res.status(401).json({
            message: "User not found"
        });
    }

    const validPassword = await bcrypt.compare(
        password,
        user.password
    );

    if (!validPassword) {
        return res.status(401).json({
            message: "Invalid password"
        });
    }

    const token = jwt.sign(
        { username: user.username },
        SECRET_KEY,
        { expiresIn: "1h" }
    );

    res.json({ token });
});

// JWT Authentication Middleware
function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).send("Token missing");
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).send("Invalid or expired token");
    }
}

// Profile
app.get("/profile", verifyToken, (req, res) => {
    res.send("Welcome " + req.user.username);
});

// Start server
app.listen(3000, () => {
    console.log("Server running at http://localhost:3000");
});
