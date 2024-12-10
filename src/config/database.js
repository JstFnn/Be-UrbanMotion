const { Sequelize } = require('sequelize');
require("dotenv").config(); 

// Create a new Sequelize instance
const sequelize = new Sequelize(process.env.DB_DBNAME, process.env.DB_USERNAME, process.env.DB_PASSWORD, {
  host: process.env.DB_HOSTNAME, 
  dialect: 'mysql', 
  port: process.env.DB_PORT,
  logging: false,  
});

// Test the connection
(async () => {
  try {
    await sequelize.authenticate();
    console.log('Connection has been established successfully.');
  } catch (error) {
    console.error('Unable to connect to the database:', error);
  }
})();

module.exports = sequelize;