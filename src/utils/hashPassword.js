const { scryptSync, randomBytes } = require('crypto');
// Hash a password
const HashPassword = (password) => {
    // Generate a salt
    const salt = randomBytes(16).toString('hex');

    // Hash the password with the salt using scryptSync
    const hashedPassword = scryptSync(password, salt, 64).toString('hex');

    // Return the salt and hashed password in a single string
    return `${salt}:${hashedPassword}`;
};

// Compare a hashed password with a plaintext password
const ComparePassword = (hashPassword, password) => {
    // Split the stored hash into salt and hashed password
    const [salt, storedHashedPassword] = hashPassword.split(':');

    // Ensure both salt and hashed password are present
    if (!salt || !storedHashedPassword) {
        throw new Error('Invalid password format');
    }

    // Hash the provided password using the stored salt
    const hashedPassword = scryptSync(password, salt, 64).toString('hex');

    // Compare the stored hashed password with the newly hashed password
    return storedHashedPassword === hashedPassword;
};




module.exports = {HashPassword, ComparePassword}