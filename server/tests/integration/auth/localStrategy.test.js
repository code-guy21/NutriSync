const request = require('supertest');
const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const { User } = require('../../../models');
const { generateVerificationToken } = require('../../../utils/email');
const bcrypt = require('bcrypt');
let server;
let app;
let mongoServer;

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

	app = require('../../../app');

	server = app.listen(0);

	await new Promise(resolve => server.once('listening', resolve));
});

afterAll(async function () {
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
		await new Promise(resolve => server.close(resolve));
	}
});

beforeEach(async function () {
	await User.deleteMany();
});

describe('passport-local', function () {
	let baseUserCredentials = {
		username: 'mockUsername',
		displayName: 'Mock User',
		email: 'mockuser@example.com',
		password: 'mockPassword123',
		profileImage: 'http://mockProfilePicUrl.org',
	};
	it('registers a user and sends a verification token', async function () {
		await request(app)
			.post('/api/auth/register')
			.send({
				...baseUserCredentials,
			})
			.expect(200);

		const user = await User.findOne({ email: 'mockuser@example.com' });

		expect(user).toBeTruthy();
		expect(user.username.toLowerCase()).toBe('mockusername');
		expect(user.displayName).toBe('Mock User');
		expect(user.email).toBe('mockuser@example.com');
		expect(await bcrypt.compare('mockPassword123', user.password)).toBe(true);
		expect(user.profileImage).toBe('http://mockProfilePicUrl.org');
		expect(user.isVerified).toBe(false);
		expect(user.verificationToken).toBeTruthy();
	});

	it("authenticates user's verification token", async function () {
		let token = generateVerificationToken();
		let user = await User.create({
			...baseUserCredentials,
			verificationToken: token,
		});

		await request(app).get(`/api/auth/verify?token=${token}`).expect(200);

		user = await User.findOne({ email: 'mockuser@example.com' });

		expect(user.isVerified).toBe(true);
		expect(user.verificationToken).toBe(null);
	});

	it('authenticates a user with email and password if account is verified', async function () {
		let user = await User.create({
			...baseUserCredentials,
			verificationToken: generateVerificationToken(),
		});

		await request(app)
			.get(`/api/auth/verify?token=${user.verificationToken}`)
			.expect(200);

		let { body } = await request(app)
			.post('/api/auth/login')
			.send({
				email: 'mockuser@example.com',
				password: 'mockPassword123',
			})
			.expect(200);

		expect(body.loggedIn).toEqual(true);
		expect(body.user.username).toEqual('mockusername');
		expect(body.user.email).toEqual('mockuser@example.com');
		expect(body.user.displayName).toEqual('Mock User');
	});

	it('logs a user out of the current session', async () => {
		await User.create({
			...baseUserCredentials,
			verificationToken: null,
			isVerified: true,
		});

		let { body } = await request(app)
			.post('/api/auth/login')
			.send({
				email: 'mockuser@example.com',
				password: 'mockPassword123',
			})
			.expect(200);

		expect(body.loggedIn).toBe(true);

		let response = await request(app).post('/api/auth/logout').expect(200);

		expect(response.body.message).toBe('User logged out');
	});

	it('should return the users information if they are authenticated', async () => {
		await User.create({
			...baseUserCredentials,
			verificationToken: null,
			isVerified: true,
		});

		let { body, headers } = await request(app)
			.post('/api/auth/login')
			.send({
				email: 'mockuser@example.com',
				password: 'mockPassword123',
			})
			.expect(200);

		expect(body.loggedIn).toBe(true);

		let {
			body: { loggedIn, user },
		} = await request(app)
			.get('/api/auth/check')
			.set('Cookie', headers['set-cookie'])
			.expect(200);

		expect(loggedIn).toBe(true);
		expect(user.username).toBe('mockusername');
		expect(user.displayName).toBe('Mock User');
		expect(user.email).toBe('mockuser@example.com');
	});
});
