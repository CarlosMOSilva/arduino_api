
const HASH1 = "1837bba45a6a7577ddf7410f21cc78d053b72238420653243692dbebfd1d6c55c34416d0b7c602b987f6d70de705f078b2c7802713629556db42b961007ee54f"
const HASH2 = "892020f3fa5995366265aed70711d245b769eb05b51942f86e150106ad897f6106fc26926b4e6ef58ad9f97536211046cc9e2dee14e666a87437058f7e2577f7"
const SALT = "3132d27d142f08a84b9c37b75bcff362";

module.exports = (req, res, next) => {

    // check for basic auth header
    if (!req.headers.authorization || req.headers.authorization.indexOf('Basic ') === -1) {
        return res.status(401).json({ message: 'Missing Authorization Header' });
    }

    // verify auth credentials
    const base64Credentials =  req.headers.authorization.split(' ')[1];
    const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
    const [username, password] = credentials.split(':');
    const user = validPassword(username, HASH1) && validPassword(password, HASH2);
    if (!user) {
        return res.status(401).json({ message: 'Invalid Authentication Credentials' });
    }
    next();
}

// Method to set salt and hash the password for a user
const setPassword = function(password) {

    // Creating a unique salt for a particular user
    this.salt = require('crypto').randomBytes(16).toString('hex');

    // Hashing user's salt and password with 1000 iterations,
    this.hash = require('crypto').pbkdf2Sync(password, SALT,
        1000, 64, `sha512`).toString(`hex`);
};

const validPassword = function(password, dbHash) {
    const hash = require('crypto').pbkdf2Sync(password, SALT, 1000, 64, `sha512`).toString(`hex`);
    return dbHash === hash;
};
