const router = require('express').Router();
const passport = require('passport');
const {
	googleCallback,
	registerUser,
	loginUser,
	verifyUser,
	checkAuthStatus,
	logoutUser,
} = require('../../controllers/authController');
require('dotenv').config();

router.route('/google').get(
	passport.authenticate('google', {
		scope: ['profile', 'email'],
		accessType: 'offline',
		prompt: 'select_account',
	})
);

router
	.route('/google/callback')
	.get(
		passport.authenticate('google', { failureRedirect: '/login' }),
		googleCallback
	);

router.route('/register').post(registerUser);

router.post('/login', (req, res, next) => {
	passport.authenticate(
		'local',
		{ keepSessionInfo: true },
		(err, user, info) => {
			if (err) {
				return res
					.status(500)
					.json({ error: 'Internal server error', details: err.message });
			}
			if (!user) {
				// User authentication failed
				return res
					.status(401)
					.json({ error: 'Authentication failed', message: info.message });
			}
			req.logIn(user, function (err) {
				if (err) {
					return res
						.status(500)
						.json({ error: 'Login error', details: err.message });
				}
				// Delegate to controller if additional processing is needed
				return loginUser(req, res);
			});
		}
	)(req, res, next);
});

router.route('/verify').get(verifyUser);

router.route('/check').get(checkAuthStatus);

router.route('/logout').post(logoutUser);

module.exports = router;
