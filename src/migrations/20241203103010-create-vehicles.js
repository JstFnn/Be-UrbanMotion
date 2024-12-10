'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  up :async (queryInterface, Sequelize) => {
    await queryInterface.createTable('vehicles', {
      id: {
        type: Sequelize.INTEGER,
        primaryKey: true,
        autoIncrement: true,
      },
      name: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      type: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      category: {
        type: Sequelize.STRING,
        allowNull: false,
      },
      transmission_type: {
        type: Sequelize.STRING,
        allowNull: true,
      },
      passenger_capacity: {
        type: Sequelize.INTEGER,
        allowNull: false,
      },
      price: {
        type: Sequelize.INTEGER,
        allowNull: false,
      },
      status: {
        type: Sequelize.STRING,
        defaultValue: 'Ready',
        allowNull: false,
      },
      air_conditioner: {
        type: Sequelize.BOOLEAN,
        allowNull: false,
      },
      doors : {
        type: Sequelize.INTEGER,
        allowNull: false,
      },
      image: {
        type: Sequelize.STRING,
        allowNull: true,
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
    await queryInterface.dropTable('vehicles');
  }
}
