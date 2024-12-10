const { v4: uuidv4 } = require('uuid');

const generateBookingId = () => {
  return uuidv4(); // Generates a unique ID like '110ec58a-a0f2-4ac4-8393-c866d813b8d1'
};

module.exports = generateBookingId;
