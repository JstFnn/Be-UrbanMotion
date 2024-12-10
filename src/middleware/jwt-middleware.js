const jwt = require('jsonwebtoken');
// require("dotenv").config(); 

const jwtMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  console.log(token);

  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET_KEY);
    req.user = decoded; // You can attach the decoded user info to the request object
    next(); // Call next to pass control to the next middleware
  } catch (err) {
    return res.status(401).json({ message: 'Token is not valid' });
  }
};

module.exports = jwtMiddleware