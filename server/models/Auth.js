const { Schema } = require('mongoose');

// Constants for enums
const { PROVIDERS } = require('../utils/constants');

/**
 * Auth Schema Definition
 *
 * This schema manages authentication data for users choosing to log in via third-party providers
 * (e.g., Google, Facebook). It stores essential information for user authentication and session management,
 * including access and refresh tokens provided by the authentication provider.
 *
 * @module Auth
 */

const authSchema = new Schema(
	{
		authProvider: {
			type: String,
			required: [true, 'Authentication provider is required'],
			enum: {
				values: Object.values(PROVIDERS),
				message: 'Unsupported authentication provider',
			},
			lowercase: true,
		},

		// Unique identifier from the authentication provider
		providerId: {
			type: String,
			required: [true, 'Provider ID is required'],
		},

		// Securely stored token for user authentication
		accessToken: {
			type: String,
			required: [true, 'Access token is required'],
		},

		// Securely stored refresh token for maintaining user sessions
		refreshToken: {
			type: String,
			required: [true, 'Refresh token is required'],
		},

		// Expiration date for the authentication token
		expirationDate: {
			type: Date,
			required: [true, 'Token expiration date is required'],
		},
	},
	{
		timestamps: {
			createdAt: 'created_at',
			updatedAt: 'updated_at',
		},
	}
);

// Export the model
module.exports = authSchema;
