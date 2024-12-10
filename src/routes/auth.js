const { Router } = require("express");
const { Login, Register, LoginByGoogle } =  require("../controller/auth.js");
const { ValidateRegisterRequest, HandleValidationErrors, ValidateLoginRequest } = require("../utils/validator.js");

const route = Router();

// Define a route
route.post("/register", ValidateRegisterRequest, HandleValidationErrors,Register);
route.post("/login", ValidateLoginRequest, HandleValidationErrors, Login);
route.post("/login/google", LoginByGoogle);


// Export the router
module.exports = route;