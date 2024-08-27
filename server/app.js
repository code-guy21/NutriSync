/**
 * Server initialization for the application.
 * Utilizes Express for the web server, Passport for authentication,
 * and MongoDB for session storage.
 *
 * Environment variables are used to configure sensitive and environment-specific options.
 */

// External module imports
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const passport = require('passport');
const path = require('path');
const cors = require('cors');
require('dotenv').config();

// Internal module imports
const connectDB = require('./config/db'); // MongoDB connection setup
const routes = require('./routes'); // API route definitions
require('./config/passport'); // Passport authentication configuration

// Server configuration
const PORT = process.env.PORT || 3001; // Server port assignment

// Express application initialization
const app = express();

//set trust proxy for deployment
app.set('trust proxy', 1);

// Session storage backend initialization
const sessionStore = MongoStore.create({ mongoUrl: process.env.MONGODB_URI }); // Session storage backend

// Session management configuration
app.use(
	session({
		secret: process.env.SESSION_SECRET || 'default_secret', // Session encryption key
		resave: false, // Avoid resaving sessions that haven't changed
		saveUninitialized: false, // Don't save new sessions that are empty
		store: sessionStore,
		cookie: {
			maxAge: 1000 * 60 * 60 * 24,
			secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
			httpOnly: process.env.NODE_ENV === 'production', // Mitigate XSS attacks by restricting cookie access from JavaScript
			sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // Strictly enforce same-site policy for cookies
		},
	})
);

// Expose sessionStore for use outside this module
app.sessionStore = sessionStore;

// Middleware setup
app.use(express.json()); // JSON parsing middleware for parsing application/json

//CORS configuration
app.use(
	cors({
		origin: process.env.CLIENT_URL,
		credentials: true,
	})
);

// Passport middleware for authentication
app.use(passport.initialize());
app.use(passport.session());

if (process.env.NODE_ENV === 'production') {
	app.use(express.static(path.join(__dirname, '../client/dist')));
}

// Initialize API routes
app.use(routes);

// Database connection and server startup
(async () => {
	try {
		if (process.env.NODE_ENV !== 'test') {
			await connectDB();
			console.log('MongoDB successfully connected.');

			app.listen(PORT, () => console.log(`Server is running on PORT: ${PORT}`));
		}
	} catch (error) {
		console.error('Database connection failed:', error);
		process.exit(1);
	}
})();

module.exports = app;
