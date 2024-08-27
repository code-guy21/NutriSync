/**
 * MongoDB Connection Initialization.
 *
 * This module establishes a connection to the MongoDB database using Mongoose.
 * It leverages environment variables for configuration to enhance security and flexibility.
 * Proper error handling mechanisms are employed to ensure reliability and maintainability.
 */

// External module imports.
const mongoose = require('mongoose');

// Load environment variables from .env file using dotenv.
require('dotenv').config();

/**
 * Initiates a connection to the MongoDB database.
 * Utilizes Mongoose for ORM capabilities and leverages connection string from environment variables.
 *
 * @async
 * @function connectDB
 * @returns {Promise<void>} Resolves upon successful connection, or rejects with an error if connection fails.
 */
const connectDB = async () => {
	try {
		await mongoose.connect(process.env.MONGODB_URI, {
			useNewUrlParser: true, // Deprecation workaround for URL string parsing.
			useUnifiedTopology: true, // Deprecation workaround for Server Discover and Monitoring engine.
		});
		console.log('MongoDB successfully connected.'); // Log on successful connection.
	} catch (error) {
		console.error('Database connection failed:', error); // Log and re-throw on connection error for further handling.
		throw error;
	}
};

module.exports = connectDB;
