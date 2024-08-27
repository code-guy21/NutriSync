/**
 * Integration tests for Google OAuth callback flow.
 *
 * This suite simulates the OAuth flow using mocked data and checks the creation or update
 * of user records upon successful authentication.
 */

const request = require('supertest');
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const { User } = require('../../../models');

// Setup in-memory database server
let mongoServer;
let app;
let server;

beforeAll(async () => {
	mongoServer = await MongoMemoryServer.create();
	const mongoUri = mongoServer.getUri();

	process.env.MONGODB_URI = mongoUri;
	console.log('Connecting to database...');
	await mongoose.connect(mongoUri, {
		useNewUrlParser: true,
		useUnifiedTopology: true,
	});
	console.log('Database connected');

	app = require('../../../app'); // Ensure app is required after the environment variable is set
	server = app.listen(0);
	await new Promise(resolve => server.once('listening', resolve)); // Ensure server is ready
});
afterAll(async () => {
	await mongoose.connection.close();

	// Close the MongoStore connection
	if (app.sessionStore && app.sessionStore.close) {
		await app.sessionStore.close();
	}

	if (mongoServer) {
		await mongoServer.stop();
		console.log('Database connection closed');
	}

	// Shut down the server
	if (server) {
		server.close();
	}
});

// Cleanup before each test
beforeEach(async () => {
	await User.deleteMany({});
	jest.clearAllMocks(); // Clear mock calls
});

// Mock Passport Google OAuth Strategy
jest.mock('passport-google-oauth20', () => {
	const originalModule = jest.requireActual('passport-google-oauth20');

	return {
		...originalModule,
		Strategy: jest.fn().mockImplementation((options, verify) => {
			return {
				name: 'google',
				authenticate: function (req, options) {
					const profile = {
						id: 'mockGoogleId123',
						displayName: 'Mock User',
						emails: [{ value: 'mockuser@example.com' }],
						photos: [{ value: 'http://mockProfilePicUrl.org' }],
						provider: 'google',
					};
					const accessToken = 'mockAccessToken';
					const refreshToken = 'mockRefreshToken';
					const params = { expires_in: 3600 };

					verify(
						accessToken,
						refreshToken,
						params,
						profile,
						(error, user, info) => {
							// Normally, Passport expects this callback to be executed with these parameters
							if (error) {
								return this.error(error);
							}
							if (!user) {
								return this.fail(info);
							}

							this.success(user, info);
						}
					);
				},
			};
		}),
	};
});

describe('Google OAuth Callback Flow', () => {
	it('should create or update a user and associate the correct Google auth method upon OAuth callback', async () => {
		const response = await request(app).get('/api/auth/google/callback');

		const savedUser = await User.findOne({ username: 'mockGoogleId123' });
		const authMethod = savedUser.authMethods.find(
			method => method.authProvider === 'google'
		);

		expect(savedUser).toBeTruthy();
		expect(savedUser.email).toBe('mockuser@example.com');
		expect(savedUser.displayName).toBe('Mock User');
		expect(savedUser.profileImage).toBe('http://mockProfilePicUrl.org');

		expect(authMethod).toBeTruthy();
		expect(authMethod.providerId).toBe('mockGoogleId123');
		expect(authMethod.accessToken).toBe('mockAccessToken');
		expect(authMethod.refreshToken).toBe('mockRefreshToken');
		expect(authMethod.expirationDate.getTime()).toBeGreaterThan(
			new Date(Date.now()).getTime()
		);
	});
});
