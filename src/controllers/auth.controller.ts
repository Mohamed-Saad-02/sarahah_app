import { User } from "../models/user.model";
import { UserType } from "../types/models/user.type";
import AppError from "../utils/appError";
import catchAsync from "../utils/catchAsync";

import bcrypt from "bcrypt";
import { emitterSendEmail } from "../services/sendEmail";
import { Encryption } from "../utils/encryption";

import jwt from "jsonwebtoken";
import { v4 as uuIdv4 } from "uuid";
import { BlackListTokens } from "../models/tokensBlackList";

// @desc    Signup user
// @route   POST /auth/signup
// @access  Public
export const signup = catchAsync(async (req, res, next) => {
  const { email, password, phone, username } = <UserType>req.body;

  // Check if user already exists
  const existingUser = await User.exists({ email });
  if (existingUser) return next(new AppError("Email already exists", 400));

  // Hash Password
  const hashedPassword = await bcrypt.hash(password, Number(process.env.SALT));

  // Encrypt Phone Number
  const encryptedPhone = Encryption({
    value: phone,
    secretKey: process.env.ENCRYPTED_KEY as string,
  });

  // Verify Email Token
  const emailToken = jwt.sign({ email }, process.env.JWT_SECRET as string, {
    expiresIn: "1h",
  });

  const confirmedEmailLink = `${req.protocol}://${req.headers.host}/auth/verify?token=${emailToken}`;

  emitterSendEmail.emit("SendEmail", {
    to: email,
    subject: "Verify you email",
    html: `
    <h1>Verify Your Email</h1>
    <p>Click on the link below to verify your email:</p>
    <a href="${confirmedEmailLink}">Verify Email</a>
    `,
  });

  // Create new user
  const newUser = await User.create({
    email,
    password: hashedPassword,
    phone: encryptedPhone,
    username,
  });

  res.status(201).json({
    status: "success",
    message: "User created successfully",
    user: {
      username: newUser.username,
      email: newUser.email,
      phone: newUser.phone,
    },
  });
});

// @desc    Signin user
// @route   POST /auth/signup
// @access  Private
export const signin = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password)
    return next(new AppError("Email or password must be provided", 404));

  // Check if user exists
  const user = await User.findOne({ email }).select([
    "password",
    "isEmailVerified",
  ]);
  if (!user) return next(new AppError("User not found", 404));

  // Check if user verified
  if (!user.isEmailVerified)
    return next(
      new AppError("Email not verified, please verify your email", 403)
    );

  // Check if password is correct
  const isCorrectPassword = await bcrypt.compare(password, user.password);
  if (!isCorrectPassword) return next(new AppError("Invalid credentials", 401));

  // Create Access Token and Refresh Token
  const access_token = jwt.sign(
    { _id: user._id },
    process.env.JWT_SECRET_LOGIN as string,
    {
      expiresIn: "12h",
      jwtid: uuIdv4(),
    }
  );
  const refresh_token = jwt.sign(
    { _id: user._id },
    process.env.JWT_SECRET_REFRESH as string,
    {
      expiresIn: "7d",
      jwtid: uuIdv4(),
    }
  );

  res.status(200).json({ status: "success", access_token, refresh_token });
});

// @desc    Verify user
// @route   POST /auth/verify
// @access  Private
export const verifyEmail = catchAsync(async (req, res, next) => {
  const { token } = req.query;
  if (!token) return next(new AppError("Token not found", 404));

  // Check if token is valid
  const { email } = jwt.verify(
    token as string,
    process.env.JWT_SECRET as string
  ) as jwt.JwtPayload;

  // Check if user exists and Verified
  const user = await User.findOneAndUpdate(
    { email },
    { isEmailVerified: true }
  );
  if (!user) return next(new AppError("User not found", 404));

  res
    .status(200)
    .json({ status: "success", message: "Email verified successfully" });
});

// @desc    Refresh token
// @route   POST /auth/refresh-token
// @access  Private
export const refreshToken = catchAsync(async (req, res, next) => {
  const { refresh_token } = req.headers;
  if (!refresh_token)
    return next(new AppError("Refresh token not provided", 401));

  // Check if refresh_token valid
  const { _id, jti: tokenId } = jwt.verify(
    refresh_token as string,
    process.env.JWT_SECRET_REFRESH as string
  ) as jwt.JwtPayload;

  // Check if token blacklisted
  const isTokenBlacklisted = await BlackListTokens.exists({ tokenId });
  if (isTokenBlacklisted) return next(new AppError("Invalid Token", 401));

  // Check if user still exists
  const user = await User.exists({ _id });
  if (!user) return next(new AppError("User no longer exist", 404));

  // Create Access Token
  const access_token = jwt.sign(
    { _id },
    process.env.JWT_SECRET_LOGIN as string
  );

  res.status(200).json({ status: "success", access_token });
});

// @desc    Signout User
// @route   POST /auth/signout
// @access  Private
export const signout = catchAsync(async (req, res, next) => {
  const { access_token, refresh_token } = req.headers;
  if (!access_token || !refresh_token)
    return next(new AppError("tokens not provided", 401));

  // Verify access token and refresh token
  const decodedAccessToken = jwt.verify(
    access_token as string,
    process.env.JWT_SECRET_LOGIN as string
  ) as jwt.JwtPayload;

  const decodedRefreshToken = jwt.verify(
    refresh_token as string,
    process.env.JWT_SECRET_REFRESH as string
  ) as jwt.JwtPayload;

  // Revoke access token and refresh token
  await BlackListTokens.insertMany(
    [decodedAccessToken, decodedRefreshToken].map((token) => ({
      tokenId: token.jti,
      expiredAt: token.exp,
    }))
  );

  res.status(200).json({ status: "success", message: "User signed out" });
});

// @desc    Forget Password User
// @route   POST /auth/forget-password
// @access  Private
export const forgetPassword = catchAsync(async (req, res, next) => {
  const { email } = req.body;
  if (!email) return next(new AppError("Email not provided", 400));

  // Check if user exists
  const user = await User.exists({ email });
  if (!user) return next(new AppError("User not found", 404));

  // Generate OTP and Send it to user
  const generateOTP = Math.floor(100000 + Math.random() * 900000);
  emitterSendEmail.emit("SendEmail", {
    to: email,
    subject: "Reset Password",
    html: `
    <h1>Reset Password</h1>
    <p>Otp is: ${generateOTP}</p>
    `,
  });

  // Hash OTP and Store it in the database
  const hashedOTP = await bcrypt.hash(
    generateOTP.toString(),
    Number(process.env.SALT)
  );

  await User.findByIdAndUpdate(user._id, { otp: hashedOTP });

  res
    .status(200)
    .json({ status: "success", message: "OTP Sent to your email" });
});

// @desc    Reset Password Of User
// @route   POST /auth/reset-password
// @access  Private
export const resetPassword = catchAsync(async (req, res, next) => {
  const { email, password, otp } = req.body;
  if (!email || !password || !otp)
    return next(new AppError("Email, password, and OTP must be provided", 400));

  // Check if user exists and OTP is correct
  const user = await User.findOne({ email }).select("+otp");

  if (!user || !user.otp)
    return next(new AppError("User not found or otp not valid", 404));

  const isCorrectOTP = await bcrypt.compare(otp, user.otp as string);
  if (!isCorrectOTP) return next(new AppError("Invalid OTP", 401));

  // Hash new password and Update user's password
  const hashedPassword = await bcrypt.hash(password, Number(process.env.SALT));
  await User.findByIdAndUpdate(user._id, {
    password: hashedPassword,
    $unset: { otp: "" },
  });

  res
    .status(200)
    .json({ status: "success", message: "Password reset successfully" });
});
