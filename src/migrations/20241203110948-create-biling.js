'use strict';

/** @type {import('sequelize-cli').Migration} */
// migrations/20241203000400-create-billing-table.js
module.exports = {
  up : async (queryInterface, Sequelize) => {
    await queryInterface.createTable('billings', {
      id: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true,
      },
      booking_id: {
        type: Sequelize.STRING,
        allowNull: false,
        references: {
          model: 'bookings',
          key: 'id',
        },
        onUpdate: 'CASCADE',
        onDelete: 'CASCADE',
      },
      total_amount: {
        type: Sequelize.INTEGER,
        allowNull: false,
      },
      payment_status: {
        type: Sequelize.STRING,
        defaultValue: 'pending',
        allowNull: false,
      },
      payment_method: {
        type: Sequelize.STRING,
        allowNull: true,
      },
      billing_date: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      createdAt: {
        type: Sequelize.DATE,
        allowNull: false,
      },
      updatedAt: {
        type: Sequelize.DATE,
        allowNull: false,
      },
    });
  },
  
   down : async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('billings');
  }
}
