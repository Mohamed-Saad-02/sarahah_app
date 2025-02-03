import { Request } from "express";
import jwt from "jsonwebtoken";
import { BlackListTokens } from "../models/tokensBlackList";
import { User } from "../models/user.model";
import AppError from "../utils/appError";
import catchAsync from "../utils/catchAsync";
import { UserType } from "../types/models/user.type";

interface AuthRequest extends Request {
  user: UserType & { token: { tokenId: string; expiredAt: number } };
}

const checkUserExist = catchAsync(async (req: AuthRequest, res, next) => {
  const { access_token } = req.headers;

  if (!access_token)
    return res.status(401).json({ message: "Access access_token is missing" });

  // Verify access_token
  const {
    _id,
    jti: tokenId,
    exp,
  } = jwt.verify(
    access_token as string,
    process.env.JWT_SECRET_LOGIN as string
  ) as jwt.JwtPayload;

  // Check if access_token is blacklisted
  const isBlacklisted = await BlackListTokens.exists({ tokenId });
  if (isBlacklisted) return next(new AppError("Invalid Token", 401));

  // Check if user exists and is verified
  const user = await User.findById(_id)
    .select(["+password", "+isEmailVerified"])
    .lean();
  if (!user) return next(new AppError("User not found", 404));

  if (!user.isEmailVerified)
    return next(new AppError("You have to verify your email", 404));

  req.user = {
    ...user,
    token: { tokenId: tokenId || "", expiredAt: exp || 0 },
  };

  next();
});

export default checkUserExist;
