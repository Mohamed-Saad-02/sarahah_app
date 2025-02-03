import { Router } from "express";
import {
  forgetPassword,
  refreshToken,
  resetPassword,
  signin,
  signout,
  signup,
  verifyEmail,
} from "../controllers/auth.controller";

const authRouter = Router();

authRouter.post("/signup", signup);
authRouter.post("/signin", signin);
authRouter.post("/verify", verifyEmail);
authRouter.post("/refresh-token", refreshToken);
authRouter.post("/signout", signout);
authRouter.patch("/forget-password", forgetPassword);
authRouter.put("/reset-password", resetPassword);

export default authRouter;
