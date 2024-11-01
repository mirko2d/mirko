import express from "express"
import cookieParser from "cookie-parser"
import morgan from "morgan"
import cors from "cors"
import jwt from "jsonwebtoken"
import crypto from "node:crypto"

const userCollection = []

const app = express()

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())
app.use(morgan("dev"))
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true,
  methods: ["GET", "POST"],
}))

// Helper functions

// Create JWT token
const createJwt = async (id) => {
  return new Promise((resolve, reject) => {
    jwt.sign({ id }, "test-key", { expiresIn: "7d" }, (err, token) => {
      if (err) {
        reject(err)
      }
      resolve(token)
    })
  })
}

// Routes

// Register
app.post("/auth/sign-up", async (req, res) => {
  const { username, email, password } = req.body

  const user = {
    id: crypto.randomUUID().toString(),
    username,
    email,
    password,
  }

  userCollection.push(user)

  const token = await createJwt(user.id)

  res.cookie("rutas-test-token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  }).json({ user, token })
})

// Login
app.post("/auth/sign-in", async (req, res) => {
  const { email, password } = req.body

  const user = userCollection.find((user) => user.email === email && user.password === password)

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" })
  }

  const token = await createJwt(user.id)

  res.cookie("rutas-test-token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  }).json({ user, token })
})

// Logout
app.get("/auth/sign-out", (req, res) => {
  res.clearCookie("rutas-test-token").json({ message: "Signed out" })
})

// Me
app.get("/auth/me", async (req, res) => {
  const token = req.cookies["rutas-test-token"]

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" })
  }

  try {
    const { id } = jwt.verify(token, "test-key")

    const user = userCollection.find((user) => user.id === id)

    if (!user) {
      return res.status(401).json({ message: "Unauthorized" })
    }

    res.json({ user })
  } catch (error) {
    res.status(401).json({ message: "Unauthorized" })
  }
})

app.listen(4000, () => {
  console.log("Server is running on port 4000")
})