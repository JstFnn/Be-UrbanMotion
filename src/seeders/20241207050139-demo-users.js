'use strict';

const { HashPassword } = require("../utils/hashPassword");

module.exports = {
  up: async (queryInterface, Sequelize) => {
    // Insert data into the Users table
    await queryInterface.bulkInsert('Users', [
      {
        username: 'John Doe',
        email: 'john.doe@gmail.com',
        password: HashPassword("password123"),
        phone_number: '08123456789',
        role: 'user',
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        username: 'admin',
        email: 'admin@admin.com',
        password: HashPassword("admin123"),
        phone_number: '08123456789',
        role: 'admin',
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ]);
  },

  down: async (queryInterface, Sequelize) => {
    // Remove data from the Users table
    await queryInterface.bulkDelete('Users', null, {});
  },
};
