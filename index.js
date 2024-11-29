import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import "dotenv/config";

const app = express();
const port = process.env.PORT || 3333;

app.use(express.json());

const users = [
  {
    id: 1,
    name: "user1",
    email: "X4E5w@example.com",
    password: bcrypt.hashSync("1234", 10),
  },
  {
    id: 2,
    name: "user2",
    email: "test@example.com",
    password: bcrypt.hashSync("Xdfio23", 10),
  },
];

const jwtSecret = process.env.JWT_SECRET;

if (!jwtSecret) {
  throw new Error("JWT_SECRET is not defined in .env file");
}

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const user = users.find((user) => user.email === email);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, jwtSecret, {
      expiresIn: "1h",
    });

    res.json({ token });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.substring(7, authHeader.length);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) {
        return res
          .status(403)
          .json({ message: "Forbidden: Invalid or expired token" });
      }
      req.user = user;
      next();
    });
  } else {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }
}

app.put("/update-email", authenticateJWT, (req, res) => {
  try {
    const { email } = req.body;
    const userId = req.user.userId;

    const user = users.find((user) => user.id === userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.email = email;
    res.json({ message: "Email updated successfully", user });
  } catch (error) {
    console.error("Error updating email:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
