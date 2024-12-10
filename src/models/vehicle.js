const { DataTypes } = require('sequelize');
const sequelize = require('../config/database.js'); // Import the Sequelize instance
const Booking = require('./booking.js');

const Vehicle = sequelize.define('Vehicle', {
  // Define model attributes
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  type: {
        type: DataTypes.STRING,
        allowNull: false,
    },
  category: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  transmission_type: {
    type: DataTypes.STRING,
    allowNull: true,  // Optional field for vehicle transmission type (e.g., manual, automatic, electric)
  },
  passenger_capacity: {
    type: DataTypes.INTEGER,
    allowNull: false,  // Optional field for passenger capacity
  },
  price : {
    type: DataTypes.INTEGER,
    allowNull: false,
  },
  image : {
    type: DataTypes.STRING,
    allowNull: true,
  },
  status: {
    type: DataTypes.STRING,
    defaultValue: 'Ready',   // The default status could be 'active'
    allowNull: false,
  },
  air_conditioner: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
  },
  doors : {
    type: DataTypes.INTEGER,
    allowNull: false,
  },
}, {
  tableName: 'vehicles', // Define the table name
  timestamps: true,      // Enable createdAt and updatedAt fields
});


Vehicle.hasMany(Booking, {
  foreignKey: 'vehicle_id',
  as: 'bookings', // Alias for accessing bookings of a vehicle
});

Booking.belongsTo(Vehicle, {
  foreignKey: 'vehicle_id',
  as: 'vehicle', // Alias for accessing the associated vehicle of a booking
});

module.exports= Vehicle;
