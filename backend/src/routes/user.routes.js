import { Router } from 'express';
import { verifyJWT } from '../middlewares/auth.middleware.js';
import {
    changeCurrentUserPassword,
    getCurrentUser,
    loginUser,
    logoutUser,
    registerUser,
    updateAccountDetails
} from '../controllers/user.controllers.js';


const router = Router();

//public routes
router.route('/register').post(registerUser);
router.route('/login').post(loginUser);

//protected routes
router.route('/change-password').post(verifyJWT, changeCurrentUserPassword);
router.route('/logout').post(verifyJWT, logoutUser);
router.route('/current-user').get(verifyJWT, getCurrentUser);
router.route('/update-account').patch(verifyJWT, updateAccountDetails);

export default router;