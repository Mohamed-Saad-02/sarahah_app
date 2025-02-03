import { Router } from "express";
import {
  getAllUsers,
  profileUser,
  updatePassword,
  updateProfile,
} from "../controllers/user.controller";
import checkUserExist from "../middlewares/checkUserExist";
import { authorizeRole } from "../middlewares/authorizeRole";

const userRouter = Router();

userRouter.get("/profile", checkUserExist, profileUser);
userRouter.patch("/update-password", checkUserExist, updatePassword);
userRouter.put("/update-profile", checkUserExist, updateProfile);

userRouter.get("/list", checkUserExist, authorizeRole(["admin"]), getAllUsers);

export default userRouter;
