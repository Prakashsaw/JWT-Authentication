import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import connectDB from "./config/connectDB.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8000;

// Database connectivity
connectDB();

//CORS Policy: Middleware
app.use(cors());
// JSON
app.use(express.json());

// API endpoints
app.use("/api/v1/users/", userRoute);

app.get("/", (req, res) => {
  res.send("Welcome to our JWT_Authentication API...");
});

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
