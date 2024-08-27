const { User } = require('../models');
const { generateVerificationToken, sendEmail } = require('../utils/email');
require('dotenv').config();

module.exports = {
	googleCallback: (req, res) => {
		res.send('Google Logged in!');
	},
	registerUser: async (req, res) => {
		try {
			let { username, displayName, email, password } = req.body;

			let user = await User.findOne({ email });

			if (user) {
				return res
					.status(400)
					.json({ message: 'Account with this email already exists' });
			}

			user = await User.findOne({ username });

			if (user) {
				return res
					.status(400)
					.json({ message: 'Account with this username already exists' });
			}

			user = await User.create({
				username,
				displayName,
				email,
				password,
				verificationToken: generateVerificationToken(),
			});

			const { password: extractedPassword, ...userWithoutPassword } =
				user.toObject();

			await sendEmail(user);

			res
				.status(200)
				.json({ message: 'User registered', user: userWithoutPassword });
		} catch (error) {
			res
				.status(500)
				.json({ error: 'Internal Server Error', details: error.message });
		}
	},
	loginUser: async (req, res) => {
		res.status(200).json({ loggedIn: true, user: req.user });
	},
	logoutUser: async (req, res) => {
		req.logout({ keepSessionInfo: true }, err => {
			if (err) {
				return res.status(400).json({ message: err.message });
			}
			res.status(200).json({ message: 'User logged out' });
		});
	},
	checkAuthStatus: async (req, res) => {
		if (req.isAuthenticated()) {
			res.status(200).json({ loggedIn: true, user: req.user });
		} else {
			res
				.status(401)
				.json({ loggedIn: false, message: 'User is unauthenticated' });
		}
	},
	verifyUser: async (req, res) => {
		try {
			let token = req.query.token;
			let user = await User.findOne({ verificationToken: token });

			if (!user) {
				return res.redirect(
					`${process.env.CLIENT_URL}/app/verify?status=failure`
				);
			}

			user.verificationToken = null;
			user.isVerified = true;

			await user.save();

			res.redirect(`${process.env.CLIENT_URL}/app/verify?status=success`);
		} catch (error) {
			res.redirect(`${process.env.CLIENT_URL}/app/verify?status=error`);
		}
	},
};
