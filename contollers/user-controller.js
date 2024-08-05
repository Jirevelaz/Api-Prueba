const Usuarios = require('../models/user');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await Usuarios.findOne({ email: email.toLowerCase() }).select('email password');
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(404).json({ message: 'Usuario o contraseña incorrectos' });
        }
        const token = jwt.sign({ id: user._id }, '1234', { expiresIn: '1d' });
        res.cookie('token', token, {
            httpOnly: true,
            secure: true,
            sameSite: 'Strict'
        });
        res.status(200).json({
            email: user.email
        });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};

exports.logout = async (req, res) => {
    res.cookie("token", "", { expires: new Date(0) });
    return res.sendStatus(200);
}


exports.register = async (req, res) => {
    const { usuario, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new Usuarios({ 
            usuario, 
            email: email.toLowerCase(), 
            password: hashedPassword 
        });
        await newUser.save();
        res.status(201).send('Usuario registrado');
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
};