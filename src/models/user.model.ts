import mongoose from "mongoose";
import validator from "validator";

import { UserSchemaType } from "../types/models/user.type";

const userSchema = new mongoose.Schema<UserSchemaType>({
  username: {
    type: String,
    lowercase: true,
    trim: true,
    unique: [true, "Username is already token"],
    required: [true, "Please provide a username"],
    minlength: [3, "Username must be at least 3 characters"],
    maxlength: [20, "Username must be at most 20 characters"],
  },
  email: {
    type: String,
    required: [true, "Please provide an email"],
    unique: [true, "Email is already token"],
    lowercase: true,
    validate: [validator.isEmail, "Please provide a valid email"],
  },
  password: {
    type: String,
    required: [true, "Please provide a password"],
    select: false,
  },
  phone: {
    type: String,
    required: [true, "Please provide a phone number"],
    unique: [true, "Phone number is already token"],
  },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },
  profileImage: String,
  isDeleted: {
    type: Boolean,
    default: false,
    select: false,
  },
  isEmailVerified: {
    type: Boolean,
    default: false,
    select: false,
  },
  otp: {
    type: String,
    select: false,
  },
});

export const User = mongoose.model<UserSchemaType>("User", userSchema);
