const { DataTypes } = require('sequelize');
const sequelize = require('../config/database.js'); // Import the Sequelize instance

const User = sequelize.define('User', {
  // Define model attributes
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    unique: true,
    allowNull: false,
  },
  phone_number: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  password: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  role: {
    type: DataTypes.STRING,
    allowNull: false,
    defaultValue: 'user',
  },
  photo_profile: {
    type: DataTypes.STRING,
    allowNull: true,
  }
}, {
  timestamps: true,   // Enable createdAt and updatedAt fields
});

module.exports = User;