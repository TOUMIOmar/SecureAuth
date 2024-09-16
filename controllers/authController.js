const axios = require('axios');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const oauth2Client = require('../utils/oauth2client');
const User = require('../models/userModel');
const nodemailer = require('nodemailer');


// Create And send Token
const signToken = (id,admin) => {
    return jwt.sign({ id,admin }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_TIMEOUT,
    });
};
// Create and send Cookie ->
const createSendToken = (user, statusCode, res) => {
    const token = signToken(user.id,user.admin);

    console.log(process.env.JWT_COOKIE_EXPIRES_IN);
    const cookieOptions = {
        expires: new Date(Date.now() + +process.env.JWT_COOKIE_EXPIRES_IN),
        httpOnly: true,
        path: '/',
        // sameSite: "none",
        secure: false,
    };
    if (process.env.NODE_ENV === 'production') {
        cookieOptions.secure = true;
        cookieOptions.sameSite = 'none';
    }

    user.password = undefined;

    res.cookie('jwt', token, cookieOptions);

    console.log(user);

    res.status(statusCode).json({
        message: 'success',
        token,
        data: {
            user,
        },
    });
};

/* GET Google Authentication API. */
const googleAuth = async (req, res, next) => {
    try {
        const code = req.query.code;
        console.log('USER CREDENTIAL -> ', code);

        const googleRes = await oauth2Client.oauth2Client.getToken(code);
        console.log('googleRes :', googleRes);

        oauth2Client.oauth2Client.setCredentials(googleRes.tokens);

        const userRes = await axios.get(
            `https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=${googleRes.tokens.access_token}`
        );

        let user = await User.findOne({ email: userRes.data.email });
        if (!user) {
            console.log('New User found');
            user = await User.create({
                name: userRes.data.name,
                email: userRes.data.email,
                image: userRes.data.picture,
            });
        }
        createSendToken(user, 201, res);
    } catch (error) {
        res.json('erro :', error);
    }
};

/*Get Facebook Authntication API */
const facebookAuth = async (req, res, next) => {
    try {
        console.log('req.body', req.body);
        const { userId, accessToken } = req.body;
        if (!userId || userId == '' || !accessToken || accessToken == '') {
            return res.json({ msg: 'userId and accessToken are required' });
        }
        // get user by facebook userId and accesToken
        const response = await axios.get(
            `https://graph.facebook.com/${userId}?fields=id,name,email&access_token=${accessToken}`
        );
        const existUser = await User.findOne({ email: response.data.email });
        if (!existUser) {
            const newUser = await User.create({
                email: response.data.email,
                name: response.data.name,
            });
            createSendToken(newUser, 201, res);
        } else {
            createSendToken(existUser, 201, res);
        }
        // res.json({ msg: 'dada', data: response.data });
    } catch (error) {
        res.json({ 'erro :': error });
    }
};

/* SignUp */
const signUp = async (req, res) => {
    try {
        const { name, email, password, image, phoneNumber } = req.body;
        const existUser = await User.findOne({ email });
        if (!existUser) {
            const user = await User.create({
                name,
                email,
                password,
                image,
                phoneNumber,
            });
            createSendToken(user, 201, res);
        } else {
            res.json({ msg: 'Account alredy exist, You can Login' });
        }
    } catch (error) {
        res.json({ msg: 'Something went wrong during sign-Up!', error });
    }
};

/* SignIn */
const signIn = async (req, res) => {
    try {
        const { email, password } = req.body;
        const existUser = await User.findOne({ email });
        if (existUser) {
            const Verify = await bcrypt.compare(password, existUser.password);
            if (Verify) {
                createSendToken(existUser, 201, res);
            } else {
                res.json({ msg: 'Wrong password Pls try again' });
            }
        } else {
            res.json({ msg: 'No account created!' });
        }
    } catch (error) {
        res.json({ msg: 'Something went wrong during signhos-Up!', error });
    }
};

/*Forget Password */
const forgetPassword = async (req, res) => {
    try {
        const { email } = req.body;
        // Find user by email
        const existUser = await User.findOne({ email: email });
        console.log('exist user', existUser);
        // If user not found ,send error message
        if (!existUser) {
            return res.stats(404).send({ msg: 'User not found' });
        }

        // Generate a unique JWT token for the user taht contains the user's id
        const token = jwt.sign({ id: existUser._id }, process.env.JWT_SECRET, {
            expiresIn: '10m',
        });
        console.log(token);
        //Send the token to the user's email
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.Email,
                pass: process.env.PASSWORD_APP_EMAIL,
            },
        });

        //Email configuration
        const mailOptions = {
            from: process.env.Email,
            to: req.body.email,
            subject: 'Reset Password',
            html: `<h1>Reset Your Password</h1>
    <p>Click on the following link to reset your password:</p>
    <a href="http://localhost:8000/reset-password/${token}">http://localhost:3000/reset-password/${token}</a>
    <p>The link will expire in 10 minutes.</p>
    <p>If you didn't request a password reset, please ignore this email.</p>`,
        };

        // Send the email
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                return res.status(500).send({ msg: err.message });
            }
            res.status(200).send({ msg: 'Email sent' });
        });
    } catch (error) {
        res.json({ msg: 'Something went wrong during Sending the email to rest password!', error });
    }
};

/*Rest Password*/
const resetPassword = async (req, res) => {
    try {
        const {token} = req.headers;
        const {password} = req.body
        // Verify the token send by the user
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

        //If the token is invalid, return an error
        if (!decodedToken) {
            return res.status(401).send({ msg: 'Invalid token' });
        }

        //Find user with the id from the token
        const user = await User.findOne({ _id: decodedToken.id });
        if (!user) {
            return res.status(401).send({ msg: 'no user found' });
        } else {
        //Update User Password
        const hashPassword=await bcrypt.hash(password,10)
        const updatedUser=await User.findByIdAndUpdate(decodedToken.id,{password:hashPassword})
        res.status(200).json({msg:"Password Updated!"})
        }
    } catch (error) {
        res.json({ msg: 'Something went wrong during Reseting the password!', error });
    }
};

/* Update User Profile */
const updateProfile = async (req, res) => {
    try {
        const { name, email, password, image, phoneNumber, user_id } = req.body;
        console.log('azer', req.body);
        const newUser = await User.findByIdAndUpdate(
            user_id,
            { name, email, password, image, phoneNumber },
            { new: true }
        );
        res.json({ msg: 'User Updated succefully', newUser });
    } catch (error) {
        res.json({ msg: 'Something went wrong during updateProfile!', error });
    }
};


module.exports = {
    googleAuth,
    signUp,
    signIn,
    updateProfile,
    facebookAuth,
    forgetPassword,
    resetPassword,
};
