const {OAuth2Client} = require("google-auth-library")
require("dotenv").config(); 

// Create a new OAuth2Client instance
const oAuth2Client = new OAuth2Client(
    process.env.OAUTH_CLIENT_ID,
    process.env.OAUTH_CLIENT_SECRET,
    'postmessage',
);

module.exports = oAuth2Client