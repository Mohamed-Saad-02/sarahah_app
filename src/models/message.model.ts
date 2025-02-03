import mongoose, { Document, ObjectId } from "mongoose";

import validator from "validator";

interface MessageSchemaType extends Document {
  receiverId: mongoose.Types.ObjectId;
  content: string;
}

const MessageSchema = new mongoose.Schema<MessageSchemaType>({
  receiverId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    validate: {
      validator: (v: ObjectId) => validator.isMongoId(v.toString()),
      message: "Id Not Valid",
    },
    select: false,
  },
  content: {
    type: String,
    required: [true, "Content must be provided"],
    trim: true,
    maxlength: [500, "Content must be less than or equal to 500 characters"],
  },
});

MessageSchema.set("toObject", { virtuals: true });
MessageSchema.set("toJSON", { virtuals: true });

// Define a virtual field to rename receiverId to user
MessageSchema.virtual("user", {
  ref: "User",
  localField: "receiverId",
  foreignField: "_id",
  justOne: true,
});

export const Message = mongoose.model<MessageSchemaType>(
  "Message",
  MessageSchema
);
