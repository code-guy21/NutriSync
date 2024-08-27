const LocalStrategy = require('passport-local').Strategy;
const { User } = require('../../models');
const bcrypt = require('bcrypt');

module.exports = new LocalStrategy(
	{
		usernameField: 'email',
		passwordField: 'password',
	},
	async function (email, password, done) {
		try {
			const user = await User.findOne({ email });

			if (!user) {
				return done(null, false, { message: 'User account not found' });
			}

			if (!user.isVerified) {
				return done(null, false, { message: 'User account is not verified' });
			}

			if (!user.password) {
				return done(null, false, {
					message: 'Password is not set, please check your login method.',
				});
			}

			let passwordCheck = await bcrypt.compare(password, user.password);

			if (!passwordCheck) {
				return done(null, false, { message: 'Invalid credentials' });
			}
			return done(null, user);
		} catch (error) {
			return done(error);
		}
	}
);
