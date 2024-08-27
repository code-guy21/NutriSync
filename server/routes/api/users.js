const router = require('express').Router();
const { registerUser } = require('../../controllers/usersController');

router.route('/').post(registerUser);

module.exports = router;
