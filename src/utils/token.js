const jwt = require('jsonwebtoken');

const GenerateAccessToken = (user) => {
    const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role }, 
        process.env.JWT_SECRET_KEY, // Make sure to set this environment variable
        { expiresIn: '1h' } // Token expiration time (1 hour)
    );

    return token
}

module.exports = {GenerateAccessToken}