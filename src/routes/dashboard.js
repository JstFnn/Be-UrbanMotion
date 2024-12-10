const { Router } = require("express");
const jwtMiddleware = require("../middleware/jwt-middleware");
const { DashboardData } = require("../controller/dashboard");


const router = Router();

router.use(jwtMiddleware)
router.get("/", DashboardData)



module.exports = router;
