const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');

const User = require('../models/user');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

exports.signup = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        const error = new Error('Validation failed.');
        error.statusCode = 422;
        error.data = errors.array();
        throw error;
    }
    const email = req.body.email;
    const name = req.body.name;
    const password = req.body.password;
    bcrypt.hash(password, 12)
        .then(hashedPw => {
            const user = new User({
                email: email,
                password: hashedPw,
                name: name
            });
            return user.save();
        }).then(result => {
            res.status(201).json({ message: 'User created', userId: result._id });
        }).catch(err => {
            if (!err.statusCode) {
                err.statusCode = 500;
            }
            next(err);
        });
};

exports.login = (req, res, next) => {
    const email = req.body.email;
    const password = req.body.password;
    let loadedUser;
    User.findOne({ email: email })
        .then(user => {
            if (!user) {
                const error = new Error('User with this email could not be found.');
                error.statusCode = 401;
                throw error;
            }
            loadedUser = user;
            return bcrypt.compare(password, user.password);
        })
        .then(isEqual => {
            if (!isEqual) {
                const error = new Error('Wrong password!');
                error.statusCode = 401;
                throw error;
            }
            const accessToken = jwt.sign({
                email: loadedUser.email,
                userId: loadedUser._id.toString()
            },
                process.env.SECRET_KEY,
                { expiresIn: '1h' });
            res.status(200).json({ accessToken: accessToken, expiresIn: 60 });
        })
        .catch(err => {
            if (!err.statusCode) {
                err.statusCode = 500;
            }
            next(err);
        });
};

exports.loginWithGoogle = (req, res, next) => {
    const { tokenId } = req.body;
    // console.log(tokenId);
    client.verifyIdToken({ idToken: tokenId, audience: process.env.GOOGLE_CLIENT_ID })
        .then(response => {
            const { email_verified, name, email } = response.getPayload();
            if (!email_verified) {
                const error = new Error('Email not verified');
                error.statusCode = 401;
                throw error;
            }
            User.findOne({ email: email }).then(userDoc => {
                if (!userDoc) {
                    let password = crypto.randomBytes(20).toString('hex');
                    const user = new User({
                        email: email,
                        password: password,
                        name: name
                    });
                    return user.save();
                } else {
                    return Promise.resolve(userDoc);
                }
            })
                .then((user) => {
                    const accessToken = jwt.sign({
                        email: user.email,
                        userId: user._id.toString()
                    },
                        process.env.SECRET_KEY,
                        { expiresIn: '1h' });
                    res.status(200).json({ accessToken: accessToken, expiresIn: 60 });
                })
                .catch(err => {
                    if (!err.statusCode) {
                        err.statusCode = 500;
                    }
                    next(err);
                });
        });
};