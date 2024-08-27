const passport = require('passport');
const setupGoogleStrategy = require('./strategies/googleStrategy');
const setupLocalStrategy = require('./strategies/localStrategy');
const { User } = require('../models');

passport.use(setupGoogleStrategy);
passport.use(setupLocalStrategy);

passport.serializeUser(function (user, done) {
	return done(null, user._id);
});
passport.deserializeUser(async function (id, done) {
	try {
		let user = await User.findById(id);

		if (!user) {
			return done(null, false);
		}
		return done(null, user);
	} catch (error) {
		return done(error, null);
	}
});
