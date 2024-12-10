const { body, validationResult } = require('express-validator');

// Validation middleware
const ValidateRegisterRequest = [
  body('username')
    .isLength({ min: 3 })
    .withMessage('Username must be at least 3 characters long')
    .notEmpty()
    .withMessage('Username is required'),

  body('email')
    .isEmail()
    .withMessage('Please provide a valid email')
    .notEmpty()
    .withMessage('Email is required'),

  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
    .notEmpty()
    .withMessage('Password is required'),

    body('phone_number')
      .matches(/^(?:\+62|62|0)8\d{8,11}$/) // Regex to validate Indonesian phone number
      .withMessage('Please provide a valid Indonesian phone number')
      .notEmpty()
      .withMessage('Phone number is required')
];

const ValidateLoginRequest = [
    body('email')
      .isEmail()
      .withMessage('Please provide a valid email')
      .notEmpty()
      .withMessage('Email is required'),
  
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters long')
      .notEmpty()
      .withMessage('Password is required'),
  ];
  

// Error handling middleware
const HandleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ 
        message: 'There were validation errors with your request.',
        errors: errors.array() 
    });
  }
  next();
};

module.exports = {ValidateRegisterRequest, ValidateLoginRequest, HandleValidationErrors}