const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');
const authSchema = require('../../models/Auth');

const Auth = mongoose.model('auth', authSchema);

let mongoServer;

beforeAll(async () => {
	mongoServer = await MongoMemoryServer.create();
	const mongoUri = mongoServer.getUri();
	await mongoose.connect(mongoUri, {
		useNewUrlParser: true,
		useUnifiedTopology: true,
	});
});

beforeEach(async () => {
	await Auth.init();
});

afterEach(async () => {
	await Auth.deleteMany({});
});

afterAll(async () => {
	await mongoose.connection.close();
	await mongoServer.stop();
	console.log('Database connection close');
});

describe('Auth Model Test', () => {
	let baseAuthData = {
		authProvider: 'Google',
		providerId: 'provider123',
		accessToken: 'encryptedToken',
		refreshToken: 'refreshToken',
		expirationDate: new Date(),
	};

	// Test Auth creation is successfull when all required fields are included
	it('should create an Auth document when all required fields are included', async () => {
		let savedAuth = await new Auth(baseAuthData).save();

		expect(savedAuth._id).toBeDefined();
		expect(savedAuth.authProvider).toEqual(
			baseAuthData.authProvider.toLowerCase()
		);
		expect(savedAuth.providerId).toEqual(baseAuthData.providerId);
		expect(savedAuth.accessToken).toEqual(baseAuthData.accessToken);
		expect(savedAuth.refreshToken).toEqual(baseAuthData.refreshToken);
		expect(savedAuth.expirationDate).toEqual(baseAuthData.expirationDate);
	});

	// Test Auth creation fails if authProvider is not from valid providers
	it('should not allow the creation of Auth document if authProvider is invalid', async () => {
		const authWithInvalidPlatform = {
			...baseAuthData,
			authProvider: 'Yahoo',
		};

		await expect(new Auth(authWithInvalidPlatform).save()).rejects.toThrow(
			mongoose.Error.ValidationError
		);
	});
	// Test Auth creation fails if required providerId is missing
	it('should not allow the creation of Auth document if providerId is missing', async () => {
		let authWithoutRequiredproviderId = {
			...baseAuthData,
			providerId: undefined,
		};

		await expect(
			new Auth(authWithoutRequiredproviderId).save()
		).rejects.toThrow(mongoose.Error.ValidationError);
	});

	// Test Auth creation fails if required accessToken is missing
	it('should not allow the creation of Auth document if accessToken is missing', async () => {
		let authWithoutRequiredaccessToken = {
			...baseAuthData,
			accessToken: undefined,
		};

		await expect(
			new Auth(authWithoutRequiredaccessToken).save()
		).rejects.toThrow(mongoose.Error.ValidationError);
	});

	// Test Auth creation fails if required refreshToken is missing
	it('should not allow the creation of Auth document if refreshToken is missing', async () => {
		let authWithoutRequiredrefreshToken = {
			...baseAuthData,
			refreshToken: undefined,
		};

		await expect(
			new Auth(authWithoutRequiredrefreshToken).save()
		).rejects.toThrow(mongoose.Error.ValidationError);
	});

	// Test Auth creation fails if required expirationDate is missing
	it('should not allow the creation of Auth document if expirationDate is missing', async () => {
		let authWithoutRequiredExpirationDate = {
			...baseAuthData,
			expirationDate: undefined,
		};

		await expect(
			new Auth(authWithoutRequiredExpirationDate).save()
		).rejects.toThrow(mongoose.Error.ValidationError);
	});
});
