/**
 * Google OAuth Strategy Configuration.
 *
 * This module configures the Google OAuth2.0 authentication strategy for Passport,
 * handling user authentication and account linking for new and returning users.
 */

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { User } = require('../../models');
require('dotenv').config();

// Google OAuth Strategy definition
module.exports = new GoogleStrategy(
	{
		clientID: process.env.GOOGLE_CLIENT_ID,
		clientSecret: process.env.GOOGLE_CLIENT_SECRET,
		callbackURL: process.env.GOOGLE_CALLBACK_URL,
	},
	async function (accessToken, refreshToken, params, profile, done) {
		try {
			let callbackData = {
				accessToken,
				refreshToken,
				expires_in: params.expires_in,
				profile: {
					id: profile.id,
					displayName: profile.displayName,
					email: profile.emails[0].value,
					profileImage: profile.photos[0].value,
					provider: profile.provider,
				},
			};
			let user = await authenticateUser(callbackData);
			return done(null, user);
		} catch (error) {
			console.error('Authentication error:', error);
			return done(error);
		}
	}
);

/**
 * Authenticate or link a user account based on the profile information
 * received from Google OAuth.
 *
 * @param {Object} callbackData - The data received from Google after successful authentication.
 * @returns {Promise<User>} The authenticated or newly linked user document.
 */

async function authenticateUser(callbackData) {
	const {
		accessToken,
		refreshToken,
		expires_in,
		profile: { id, email, displayName, profileImage, provider },
	} = callbackData;

	try {
		let user = await User.findOne({ email }).populate('authMethods');

		if (!user) {
			user = new User({
				username: id,
				displayName,
				email,
				profileImage,
				isVerified: true,
			});
		}

		// Update or add Google auth method
		const authMethodIndex = user.authMethods.findIndex(
			method => method.authProvider === provider
		);
		const authData = {
			authProvider: provider,
			providerId: id,
			accessToken,
			refreshToken,
			expirationDate: new Date(Date.now() + expires_in * 1000),
		};

		if (authMethodIndex > -1) {
			user.authMethods[authMethodIndex] = authData;
		} else {
			user.authMethods.push(authData);
		}

		await user.save();
		return user;
	} catch (error) {
		console.error('Error in authenticateOrLinkUser:', error);
		throw error;
	}
}
