function isAuthenticated(req, res, next) {
	if (!req.user || !req.isAuthenticated()) {
		return res.status(401).json({ message: 'User is not authenticated' });
	}

	next();
}

module.exports = isAuthenticated;
