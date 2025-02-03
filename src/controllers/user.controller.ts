import { Request } from "express";
import { UserType } from "../types/models/user.type";
import catchAsync from "../utils/catchAsync";
import { Decryption, Encryption } from "../utils/encryption";

import bcrypt from "bcrypt";
import { BlackListTokens } from "../models/tokensBlackList";
import { User } from "../models/user.model";
import AppError from "../utils/appError";

import jwt from "jsonwebtoken";
import { emitterSendEmail } from "../services/sendEmail";

import { v4 as uuIdv4 } from "uuid";
import { requestType } from "../types/controllers/middleware.type";

// @desc    Get User Detail
// @route   POST /users/profile
// @access  Private
export const profileUser = catchAsync(
  async (req: Request & { user: UserType }, res, next) => {
    const { user: { phone = "", email, username, profileImage } = {} } = req;

    // Decrypt phone number
    let encryptionPhone = Decryption({
      cipher: phone,
      secretKey: process.env.ENCRYPTED_KEY as string,
    });

    res.status(200).json({
      status: "success",
      user: {
        phone: encryptionPhone,
        email,
        username,
        profileImage,
      },
    });
  }
);

// @desc    Update User Password
// @route   POST /users/update-password
// @access  Private
export const updatePassword = catchAsync(
  async (req: requestType, res, next) => {
    const { _id, password } = req.user;
    const { tokenId, expiredAt } = req.user.token;

    const { oldPassword, newPassword } = req.body;

    // Check if old password is correct
    const isCorrectPassword = await bcrypt.compare(oldPassword, password);
    if (!isCorrectPassword)
      return next(new AppError("Incorrect old password", 401));

    // Hash new Password and Update
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(_id, { password: hashedPassword });

    // Revoke Access token
    await BlackListTokens.create({ tokenId, expiredAt });

    res.status(200).json({
      status: "success",
      message: "Password updated successfully",
    });
  }
);

// @desc    Update User Profile
// @route   POST /users/update-profile
// @access  Private
export const updateProfile = catchAsync(async (req: requestType, res, next) => {
  const { _id } = req.user;
  const { username, email, phone } = req.body;

  console.log(phone);

  const updateData: Partial<UserType> = {};

  // Check if username already exists
  if (username) {
    const existingUser = await User.findOne({ username });
    if (existingUser) return next(new AppError("Username already exists", 400));

    updateData.username = username;
  }

  // Check if email already exists
  if (email) {
    const existingUser = await User.findOne({ email });
    if (existingUser) return next(new AppError("Email already exists", 400));

    updateData.email = email;
    updateData.isEmailVerified = false;

    // Generate new JWT token for email verification and send it
    const emailToken = jwt.sign({ email }, process.env.JWT_SECRET as string, {
      expiresIn: "1h",
      jwtid: uuIdv4(),
    });
    const confirmedEmailLink = `${req.protocol}://${req.headers.host}/auth/verify?token=${emailToken}`;
    emitterSendEmail.emit("SendEmail", {
      to: email,
      subject: "Update Profile",
      html: `
    <h1>Update Profile</h1>
    <p>Your profile has been updated successfully.</p>
    <p>Click on the link below to access your updated profile:</p>
    <a href="${confirmedEmailLink}">Verify Email</a>
    `,
    });
  }

  // Decrypt phone number if provided
  if (phone) {
    updateData.phone = Encryption({
      value: phone,
      secretKey: process.env.ENCRYPTED_KEY as string,
    });
  }

  // Update User
  await User.findByIdAndUpdate(_id, updateData);

  res.status(200).json({
    status: "success",
    message: "Profile updated successfully",
  });
});

// @desc    Get All Users
// @route   POST /users/list
// @access  Private
export const getAllUsers = catchAsync(async (req, res, next) => {
  const users = await User.find({ isDeleted: false });

  res.status(200).json({
    status: "success",
    users,
  });
});
