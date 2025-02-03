import { Application } from "express";

import authRouter from "./auth.route";
import userRouter from "./user.route";
import messageRouter from "./message.route";

const mountRoutes = (app: Application): void => {
  // Add routes here
  app.use("/auth", authRouter);
  app.use("/users", userRouter);
  app.use("/messages", messageRouter);
};

export { mountRoutes };
