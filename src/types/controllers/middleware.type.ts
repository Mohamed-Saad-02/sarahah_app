import { Request } from "express";
import { UserType } from "../models/user.type";

// Contain type information about the user that came from the checkUserExist middleware
export interface requestType extends Request {
  user: Omit<UserType, "otp"> & {
    _id: string;
    token: { tokenId: string; expiredAt: number };
  };
  token: { tokenId: string; expiredAt: string };
}
