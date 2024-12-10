const { DataTypes } = require('sequelize');
const sequelize = require('../config/database.js'); // Import the Sequelize instance

const Billing = sequelize.define('Billing', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  booking_id: {
    type: DataTypes.STRING,
    allowNull: false,  // Foreign key to associate the billing with a car rental
    references: {
      model: 'bookings',  // Refers to the 'car_rentals' table where rental bookings are stored
      key: 'id',
    },
  },
  total_amount: {
    type: DataTypes.INTEGER,
    allowNull: false,  // The total amount to be billed
  },
  payment_status: {
    type: DataTypes.STRING,
    defaultValue: 'pending', // Default payment status (could be 'pending', 'paid', 'failed')
    allowNull: false,
  },
  payment_method: {
    type: DataTypes.STRING,
    allowNull: true,  // Payment method (e.g., 'credit card', 'bank transfer', 'paypal')
  },
  billing_date: {
    type: DataTypes.DATE,
    allowNull: false,  // The date the billing occurred
  },
}, {
  tableName: 'billings', // Define the table name
  timestamps: true,      // Enable createdAt and updatedAt fields
});

module.exports= Billing
