'use strict';

const generateBookingId = require('../utils/generatorID');

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  up: async (queryInterface, Sequelize) => {
    const bookings = [];
    const billings = [];

    // Helper function to randomize payment status
    const randomPaymentStatus = () => {
      const statuses = ['pending', 'completed', 'canceled'];
      return statuses[Math.floor(Math.random() * statuses.length)];
    };

    const randomDriver = () => {
      const options = ["tanpa driver", "laki-laki", "perempuan"];
      return options[Math.floor(Math.random() * options.length)];
    };

    const randomPaymentMethod = () => {
      const methods = ['credit card', 'bank transfer', 'bri_va', 'bni_va', 'echannel', 'gopay'];
      return methods[Math.floor(Math.random() * methods.length)];
    };

    for (let i = 1; i <= 50; i++) {
      const bookingId = generateBookingId();
      const bookingDate = new Date(2024, (i % 12), Math.min(i, 28)); // Distribute across months
      const totalDays = Math.ceil(Math.random() * 7); // Random rental duration between 1-7 days
      const totalAmount = totalDays * 400000; // Example calculation based on daily rate
      const vehicleId = (i % 15) + 1; // Cycle through vehicle IDs 1-15

      // Create Booking Entry
      bookings.push({
        id: bookingId,
        user_id: 1,
        username: `John Doe${i}`,
        email: `john.doe${i}@example.com`,
        phone_number: `081234567${i.toString().padStart(3, '0')}`,
        address: `Depok ${i}`,
        vehicle_id: vehicleId,
        rental_date: bookingDate,
        driver: randomDriver(),
        total_days: totalDays,
        total_amount: randomDriver() !== "tanpa driver" ? totalAmount + 200000 : totalAmount,
        status: randomPaymentStatus(),
        createdAt: bookingDate,
        updatedAt: bookingDate,
      });

      // Create Billing Entry
      billings.push({
        id: i,
        booking_id: bookingId,
        total_amount: randomDriver() !== "tanpa driver" ? totalAmount + 200000 : totalAmount,
        payment_status: randomPaymentStatus(), // Randomized status
        payment_method: randomPaymentMethod(),
        billing_date: bookingDate,
        createdAt: bookingDate,
        updatedAt: bookingDate,
      });
    }

    // Insert Data into Tables
    await queryInterface.bulkInsert('bookings', bookings, {});
    await queryInterface.bulkInsert('billings', billings, {});
  },

  down: async (queryInterface, Sequelize) => {
    // Delete Seed Data
    await queryInterface.bulkDelete('bookings', null, {});
    await queryInterface.bulkDelete('billings', null, {});
  }
};
