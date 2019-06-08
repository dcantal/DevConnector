const jwt = require('jsonwebtoken');
const config = require('config');

module.exports = function(req, res, next) {

    // Get token from header 
    const token = req.header('x-auth-token');

    // Check if no token
    if(!token) {
        // 401 - not authorized
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    // Verify token
    try {
        // decode token with verify
        const decoded = jwt.verify(token, config.get('jwtSecret'));

        // assign value to req.user
        req.user = decoded.user;
        next();
    } catch(err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};