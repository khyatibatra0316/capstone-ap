import express from "express";
import cors from "cors";
import 'dotenv/config';
import cookieParser from "cookie-parser";
import connectDB from "./config/mongodb.js";

import authRouter from "./routes/authRoutes.js";
import userRouter from "./routes/userRoutes.js";
import bookRoutes from "./routes/bookRoutes.js"; // <-- FIXED

const app = express();
const port = process.env.PORT || 4000;

// Connect Database
connectDB();

// Middleware
app.use(express.json());
app.use(cookieParser());

app.use(cors({
  origin: "http://localhost:5173",
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true,
}));


// Routes
app.get("/", (req, res) => res.send("API working"));
app.use("/api/auth", authRouter);
app.use("/api/user", userRouter);
app.use("/api/books", bookRoutes);

// Start Server
app.listen(port, () => console.log(`Server is running on PORT: ${port}`));
