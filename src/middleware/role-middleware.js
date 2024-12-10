const checkRole = (allowedRoles) => {
    return (req, res, next) => {
      try {
        const userRole = req.user?.role; // Assuming `req.user` contains the user's role

        console.log(userRole);
  
        if (!userRole) {
          return res.status(401).json({ error: 'Unauthorized: No role found' });
        }
  
        if (!allowedRoles.includes(userRole)) {
          return res.status(403).json({ error: 'Forbidden: Insufficient role' });
        }
  
        next(); // Proceed to the next middleware or route handler
      } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
      }
    };
  };
  
  module.exports = checkRole;