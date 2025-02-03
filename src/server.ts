import dotenv from "dotenv";
import mongoose from "mongoose";

import path = require("node:path");
dotenv.config({ path: path.resolve("config.env") });

import app from "./app";

process.on("uncaughtException", (err) => {
  console.log("UNCAUGHT REJECTION! 💥 Shutting down...");
  console.log(err.name, err.message);
});

const DB = process.env.DATABASE_LOCAL;

// Connect DB
mongoose
  .connect(DB as string)
  .then(() => console.log("Connected DB 📒"))
  .catch((err) => console.log("DB Failed Connected ", err.message));

const port = process.env.PORT || 8000;
const server = app.listen(port, () => {
  console.log(`App running on port ${port}...`);
});

// Handle Async Promise Rejection
process.on("unhandledRejection", (err: Error) => {
  console.log(err.name, err.message);
  console.log("UNHANDLED REJECTION! 💥 Shutting down...");
  server.close(() => process.exit(1));
});
