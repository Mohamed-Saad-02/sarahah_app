import { UserType } from "../types/models/user.type";
import AppError from "../utils/appError";
import catchAsync from "../utils/catchAsync";
import { Request } from "express";

/**
 * Middleware to authorize user roles
 *
 * @param  {...string} roles - Roles to authorize
 * @returns {Function} Middleware function for role-based authorization
 */

interface AuthRequest extends Request {
  user: Pick<UserType, "role">;
}

export const authorizeRole = (roles: Array<UserType["role"]>) =>
  catchAsync(async (req: AuthRequest, res, next) => {
    // Get user that passed from checkUserExist middleware
    const { user } = req;

    if (!roles.includes(user.role)) {
      return next(
        new AppError("You don't have permission to perform this action", 403)
      );
    }

    next();
  });
