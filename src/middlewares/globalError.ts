import { Request, Response, NextFunction } from "express";
import AppError from "../utils/appError";

interface MongoError extends Error {
  code?: number;
  keyValue?: string;
  errors?: Record<string, { message: string }>;
  path?: string;
  value?: string;
  statusCode?: number;
  status?: string;
}

// Handle Mongoose CastError (Invalid ObjectId)
const handleCastErrorDB = (err: MongoError): AppError => {
  const message = `Invalid ${err.path}: ${err.value}`;
  return new AppError(message, 400);
};

// Handle Mongoose Duplicate Key Error
const handleDuplicateFieldsDB = (err: MongoError): AppError => {
  const values = Object.entries(err.keyValue || {})
    .map(([key, value]) => `${key}: ${value}`)
    .join(", ");

  const message = `Duplicate field value: ${values}. Please use another value!`;
  return new AppError(message, 400);
};

// Handle Mongoose Validation Errors
const handleValidationErrorDB = (err: MongoError): AppError => {
  const values = Object.values(err.errors || {})
    .map((el) => el.message)
    .join(". ");

  const message = `Validation error: ${values}. Please use another value!`;
  return new AppError(message, 400);
};

// Handle Invalid JWT
const handleJWTError = (): AppError =>
  new AppError("Invalid token. Please login again", 401);

// Handle Expired JWT
const handleJWTExpiredError = (): AppError =>
  new AppError("Your token has expired! Please login again", 401);

// Send Error Response in Development Mode
const sendErrorDev = (err: AppError, res: Response): void => {
  res.status(err.statusCode).json({
    status: err.status,
    message: err.message,
    stack: err.stack,
    error: err,
  });
};

// Send Error Response in Production Mode
const sendErrorProd = (err: AppError, res: Response): void => {
  if (err.isOperational) {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  } else {
    console.error("ERROR 💥", err);

    res.status(500).json({
      status: "error",
      message: "Something went very wrong!",
    });
  }
};

// Global Error Handling Middleware
const globalError = (
  err: MongoError,
  req: Request,
  res: Response,
  next: NextFunction
): void => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || "error";

  if (process.env.NODE_ENV === "development") {
    sendErrorDev(err as AppError, res);
  } else if (process.env.NODE_ENV === "production") {
    let error = { ...err, message: err.message };

    if (err.name === "CastError") error = handleCastErrorDB(err);
    if (err.code === 11000) error = handleDuplicateFieldsDB(err);
    if (err.name === "ValidationError") error = handleValidationErrorDB(err);
    if (err.name === "JsonWebTokenError") error = handleJWTError();
    if (err.name === "TokenExpiredError") error = handleJWTExpiredError();

    sendErrorProd(error as AppError, res);
  }
};

export default globalError;
