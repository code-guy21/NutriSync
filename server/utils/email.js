const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const transporter = nodemailer.createTransport({
	host: 'smtp.sendgrid.net',
	port: '587',
	secure: false,
	auth: {
		user: 'apikey',
		pass: process.env.SENDGRID_API_KEY,
	},
});

function generateVerificationToken() {
	return crypto.randomBytes(32).toString('hex');
}

async function sendEmail(user) {
	try {
		const mailOptions = {
			from: '"NutriSync Support" <support@nutrisync.com>',
			to: user.email,
			subject: 'Email Verification',
			html: ` <div style="font-family: Arial, sans-serif; color: #333; padding: 20px; line-height: 1.6;">
				<h2 style="color: #4CAF50;">Welcome to NutriSync, ${user.username}!</h2>
				<p>Thank you for signing up. To start your nutrition journey, please verify your email address by clicking the button below:</p>
				<a href="${process.env.SENDGRID_CALLBACK}?token=${user.verificationToken}" 
				   style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">
				  Verify Email
				</a>
				<p>If the button above doesn't work, copy and paste the following link into your browser:</p>
				<p><a href="${process.env.SENDGRID_CALLBACK}?token=${user.verificationToken}" 
					  style="color: #4CAF50;">${process.env.SENDGRID_CALLBACK}?token=${user.verificationToken}</a></p>
				<p>If you did not create an account with NutriSync, please ignore this email.</p>
				<p>Thank you,<br/>The NutriSync Team</p>
			  </div>`,
		};

		const info = await transporter.sendMail(mailOptions);

		console.log(info);
	} catch (error) {
		console.log(error);
	}
}

module.exports = { generateVerificationToken, sendEmail };
