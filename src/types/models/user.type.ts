import { Document } from "mongoose";

export interface UserType {
  username: string;
  email: string;
  password: string;
  phone: string;
  profileImage: string;
  isDeleted?: boolean;
  isEmailVerified?: boolean;
  otp?: string;
  role: "admin" | "user";
}

export interface UserSchemaType extends Document, UserType {}
