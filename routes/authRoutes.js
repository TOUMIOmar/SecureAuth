const express = require('express');
const {googleAuth,signUp,signIn,updateProfile,facebookAuth,forgetPassword,resetPassword,signInAdmin} = require('../controllers/authController');
const userMiddleware = require('../middleware/userMiddleware');

const Router = express.Router();


Router.get("/google", googleAuth);
Router.post("/signup",signUp)
Router.post("/signin",signIn)
Router.put("/updateprofile",userMiddleware,updateProfile)
Router.post("/forgetpassword",forgetPassword)
Router.post("/resetpassword",resetPassword)
Router.post("/facebook",facebookAuth)

/* Admin Login */
Router.post("/admin/signin",signInAdmin)





module.exports = Router;