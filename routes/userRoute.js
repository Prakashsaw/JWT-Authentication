import express from 'express';
const router =  express.Router();
import userController from '../controllers/userController.js';
import checkUserAuth from '../middlewares/auth-middleware.js';


// Route level moddleware - To Protect Route
router.use("/changepassword", checkUserAuth);
router.use("/loggeduser", checkUserAuth);

// Public routes
// Like: login, regieter, etc
router.post("/register", userController.userRegistration);
router.post("/login", userController.userLogin);
router.post("/send-reset-password-email", userController.sendUserPasswordResetEmail);
router.post("/reset-password/:id/:token", userController.userPasswordReset)


// Protected Route
// Like: Access to dashboard, change password, forgot password, etc
router.post("/changepassword", userController.changeUserPassword);
router.get("/loggeduser", userController.loggedUser);


export default router;