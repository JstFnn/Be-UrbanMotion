const { DataTypes } = require('sequelize');
const sequelize = require('../config/database.js'); // Import the Sequelize instance

const Booking = sequelize.define('Booking', {
  // Define model attributes
  id: {
    type: DataTypes.STRING,
    primaryKey: true,
    allowNull: false,
  },
  user_id: {
    type: DataTypes.INTEGER,
    allowNull: false,  // Foreign key to associate the booking with a user
    references: {
      model: 'users',   // Refers to the 'users' table where user details are stored
      key: 'id',
    },
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  phone_number: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  address: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  vehicle_id: {
    type: DataTypes.INTEGER,
    allowNull: false,  // Foreign key to associate the booking with a vehicle
    references: {
      model: 'vehicles',  // Refers to the 'vehicles' table where vehicle details are stored
      key: 'id',
    },
  },
  rental_date: {
    type: DataTypes.DATE,
    allowNull: false,
  },
  driver: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  total_days: {
    type: DataTypes.INTEGER,
    allowNull: false,
  },
  total_amount: {
    type: DataTypes.INTEGER,
    allowNull: false,
  },
  status: {
    type: DataTypes.STRING,
    defaultValue: 'pending', // Default status could be 'pending'
    allowNull: false,
  },
}, {
  tableName: 'bookings', // Define the table name
  timestamps: true,         // Enable createdAt and updatedAt fields
});
module.exports= Booking;