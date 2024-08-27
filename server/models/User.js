const { Schema, model } = require('mongoose');
const validator = require('validator');
const authSchema = require('./Auth');
const bcrypt = require('bcrypt');

/**
 * Defines schema for users within the NutriSync application.
 * This schema encompasses various aspects of a user's profile, including
 * authentication methods, linked streaming services, and content interactions.
 * It serves as a model for user data management and interactions.
 *
 * @module UserModel
 */
const userSchema = new Schema(
	{
		// Username for login and internal identification
		username: {
			type: String,
			required: [true, 'Username is required'],
			trim: true,
			unique: true,
			lowercase: true,
			validate: [
				validator.isAlphanumeric,
				'Username contains invalid characters',
			],
		},
		// User's display name for public profile
		displayName: {
			type: String,
			required: [true, 'Display name is required.'],
			trim: true,
			maxLength: [50, 'Display name cannot exceed 50 characters'],
		},
		// User email for identification and communication
		email: {
			type: String,
			required: [true, 'Email address is required.'],
			unique: true,
			trim: true,
			lowercase: true,
			validate: [validator.isEmail, 'Invalid email address'],
		},
		password: {
			type: String,
			trim: true,
			minLength: [8, 'Password must be at least 8 characters long'],
		},
		verificationToken: {
			type: String,
		},
		isVerified: {
			type: Boolean,
			default: false,
		},
		// URL to the user's profile image
		profileImage: {
			type: String,
			trim: true,
			validate: [validator.isURL, 'Invalid URL for profile image'],
		},
		// User's bio
		bio: {
			type: String,
			trim: true,
			maxLength: [160, 'Bio cannot exceed 160 characters'],
		},

		// Authentication methods linked to user
		authMethods: [authSchema],
	},
	{
		timestamps: true,
		toJSON: { virtuals: true },
		toObject: { virtuals: true },
	}
);

userSchema.pre('save', async function (next) {
	if (this.password) {
		if (this.isModified('password') || this.isNew) {
			try {
				const salt = await bcrypt.genSalt(10);
				this.password = await bcrypt.hash(this.password, salt);
				next();
			} catch (err) {
				next(err);
			}
		}
	} else {
		next();
	}
});

userSchema.methods.toJSON = function () {
	let obj = this.toObject();
	delete obj.password;
	delete obj.isVerified;
	delete obj.verificationToken;
	delete obj.__v;
	return obj;
};

// Indexes for efficient querying
userSchema.index({ username: 1 }, { unique: true });
userSchema.index({ email: 1 }, { unique: true });

// Compile model from schema
const User = model('user', userSchema);

// Export the model
module.exports = User;
