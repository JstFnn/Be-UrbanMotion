const midtransClient = require('midtrans-client');
require("dotenv").config(); 

// Create a new MidtransClient instance
const SnapApi = new midtransClient.Snap({
  isProduction: false,
  serverKey: process.env.MIDTRANS_SERVER_KEY,
  clientKey: process.env.MIDTRANS_CLIENT_KEY,
});

module.exports = SnapApi;