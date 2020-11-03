const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

const authRoutes = require('./routes/auth');

const app = express();

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

app.use(bodyParser.json());

app.use('/auth', authRoutes);

app.use((error, req, res, next) => {
    const status = error.statusCode || 500;
    const message = error.message || 'Something went wrong!';
    const data = error.data || 'No data.';
    res.status(status).json({ message: message, data: data });
});

mongoose
    .connect(
        process.env.DB_HOST,
        {
            useUnifiedTopology: true,
            useNewUrlParser: true
        }
    )
    .then(result => {
        app.listen(process.env.PORT || 8000);
    }).catch(err => console.log(err));