import mongoose from "mongoose";
import { Message } from "../models/message.model";
import { User } from "../models/user.model";
import { requestType } from "../types/controllers/middleware.type";
import catchAsync from "../utils/catchAsync";

// @desc    Send Message To user
// @route   POST /messages/send
// @access  Public
export const sendMessage = catchAsync(async (req, res, next) => {
  const { content, receiverId } = req.body;

  // Check if the receiver exists
  const userExists = await User.exists({ _id: receiverId });
  if (!userExists) return next(new Error("User not found"));

  // Save the message in the database
  const message = await Message.create({
    receiverId,
    content,
  });

  // Return the sent message
  res
    .status(200)
    .json({ status: "success", message: "Message sent successfully" });
});

// @desc    Send Message To user
// @route   GET /messages/user
// @access  Public
export const getMessagesUser = catchAsync(
  async (req: requestType, res, next) => {
    const { _id } = req.user;

    // Get All messages about the receiver
    const messages = await Message.find({ receiverId: _id })
      .select("content")
      .populate<mongoose.PopulateOptions>({
        path: "user",
        select: ["username", "-_id"],
      });

    // Return the sent message
    res.status(200).json({ status: "success", messages });
  }
);
