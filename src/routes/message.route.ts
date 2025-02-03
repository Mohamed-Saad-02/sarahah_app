import { Router } from "express";
import {
  getMessagesUser,
  sendMessage,
} from "../controllers/message.controller";
import checkUserExist from "../middlewares/checkUserExist";

const messageRouter = Router();

messageRouter.post("/send", sendMessage);
messageRouter.get("/user", checkUserExist, getMessagesUser);

export default messageRouter;
