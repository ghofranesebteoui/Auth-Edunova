// utils/sendEmail.js
const nodemailer = require("nodemailer");

const sendEmail = async (options) => {
  // Pour tester localement : utilisez Ethereal (fausses emails)
  const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    auth: {
      user: "ghofranesebteoui16@gmail.com", // créez un compte gratuit sur ethereal.email
      pass: "hattkhgedvbeyoms",
    },
  });

  // Pour Gmail (production) :
  // host: 'smtp.gmail.com',
  // port: 587,
  // auth: { user: 'votre@gmail.com', pass: 'votre-app-password' }

  const mailOptions = {
    from: "EduNova <no-reply@edunova.com>",
    to: options.email,
    subject: options.subject,
    text: options.message,
    html: options.html,
  };

  await transporter.sendMail(mailOptions);
};

module.exports = sendEmail;
