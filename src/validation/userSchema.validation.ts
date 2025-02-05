import Joi from "joi";

export const signupSchema = Joi.object({
  username: Joi.string().lowercase().trim().min(3).max(20).required().messages({
    "string.base": "Username should be a type of 'text'",
    "string.empty": "Please provide a username",
    "string.min": "Username must be at least 3 characters",
    "string.max": "Username must be at most 20 characters",
    "any.required": "Please provide a username",
  }),
  email: Joi.string().email().lowercase().required().messages({
    "string.email": "Please provide a valid email",
    "string.empty": "Please provide an email",
    "any.required": "Please provide an email",
  }),
  password: Joi.string().required().messages({
    "string.empty": "Please provide a password",
    "any.required": "Please provide a password",
  }),
  phone: Joi.string().required().messages({
    "string.empty": "Please provide a phone number",
    "any.required": "Please provide a phone number",
  }),
  role: Joi.string().valid("user", "admin").default("user"),
  profileImage: Joi.string().optional(),
  isDeleted: Joi.boolean().forbidden(),
  isEmailVerified: Joi.boolean().forbidden(),
  otp: Joi.string().forbidden(),
});
