import { NextFunction, Request, RequestHandler, Response } from "express";

const catchAsync =
  (fn: RequestHandler | Function): RequestHandler =>
  (req: Request, res: Response, next: NextFunction): Promise<void> => {
    return Promise.resolve(fn(req, res, next)).catch(next);
  };

export default catchAsync;
