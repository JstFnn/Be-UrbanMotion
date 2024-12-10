const { Router } = require("express");
const jwtMiddleware = require("../middleware/jwt-middleware");
const { GetUserByID, UpdateUser } = require("../controller/user");
const upload = require("../config/uploader");
const checkRole = require("../middleware/role-middleware");


const router = Router();

router.use(jwtMiddleware)
router.get('/profile',  checkRole(["user", "admin"]), GetUserByID)
router.put('/profile',  checkRole(["user", "admin"]), upload.single("image"),UpdateUser)


module.exports = router