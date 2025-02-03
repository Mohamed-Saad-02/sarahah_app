import * as nodemailer from "nodemailer";

import { EventEmitter } from "node:events";

interface SendEmailType extends nodemailer.SendMailOptions {}

type EmailOptions = Pick<
  SendEmailType,
  "to" | "subject" | "html" | "attachments"
>;

export const sendEmailService = async ({
  to,
  subject,
  html,
  attachments,
}: EmailOptions) => {
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com", //smtp.gmail.com
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    // tls: { rejectUnauthorized: false },
  });

  const info = await transporter.sendMail({
    from: `Sarahah <${process.env.EMAIL_USER}>`,
    to,
    subject,
    html,
    attachments,
  });

  return info;
};

export const emitterSendEmail = new EventEmitter();

emitterSendEmail.on("SendEmail", (...args: EmailOptions[]): void => {
  if (!args.length && !args[0].to) return;
  sendEmailService(args[0]);
});
