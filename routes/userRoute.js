import express from 'express';
const router =  express.Router();
import userController from '../controllers/userController.js';

// Public routes
// Like: login, regieter, etc
router.post("/register", userController.userRegistration);
router.post("/login", userController.userLogin);
// Protected Route
// Like: Access to dashboard, change password, forgot password, etc


export default router;