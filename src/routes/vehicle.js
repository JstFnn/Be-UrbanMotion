

const { Router } = require("express");
const { GetVehicles, GetVehicleByID, CreateVehicle, UpdateVehicle, DeleteVehicle } = require("../controller/vehicle");
const upload = require("../config/uploader");
const jwtMiddleware = require("../middleware/jwt-middleware");
const checkRole = require("../middleware/role-middleware");

const route = Router();

// Define a route
route.get("/", GetVehicles);
route.get('/:vehicleID', GetVehicleByID)
route.use(jwtMiddleware)
route.post('/', checkRole(["admin"]), upload.single("image"), CreateVehicle)
route.put('/:vehicleID', checkRole(["admin"]),upload.single("image"), UpdateVehicle)
route.delete('/:vehicleID', checkRole(["admin"]), DeleteVehicle)

// Export the router
module.exports = route;