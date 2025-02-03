import { TokenExpiredError } from "jsonwebtoken";
import mongoose, { Document } from "mongoose";

interface TokensBlackListType extends Document {
  tokenId: string;
  expiredAt: string;
}

const BlackListTokensSchema = new mongoose.Schema<TokensBlackListType>({
  tokenId: {
    type: String,
    required: true,
    unique: [true, "Invalid token"],
  },
  expiredAt: {
    type: String,
    required: true,
  },
});

export const BlackListTokens = mongoose.model<TokensBlackListType>(
  "BlackListTokens",
  BlackListTokensSchema
);
