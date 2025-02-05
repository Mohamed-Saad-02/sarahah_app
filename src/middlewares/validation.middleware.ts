import { NextFunction, Request, Response, RequestHandler } from "express";
import { Schema } from "joi";

const validateSchema = (schema: Schema): RequestHandler => {
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const { error } = schema.validate(req.body, {
      abortEarly: false,
      allowUnknown: true,
      stripUnknown: true,
    });

    if (error) {
      const errorDetails = error.details.map((detail) => detail.message);
      res.status(400).json({ status: "fail", errors: errorDetails });
      return;
    }

    next();
  };
};

export default validateSchema;
