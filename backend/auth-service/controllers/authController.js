const exp = require('constants')
const jwt = require('jsonwebtoken')
const User = require('../models/User')
const { sign } = require('crypto')

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  })
}

exports.signup = async (req, res, next) => {
	try {
		const newUser = await UserActivation.create({
			name: req.body.name,
			email: req.body.email,
			password: req.body.password,
			passwordConfirm: req.body.passwordConfirm,
		})

		const token = signToken(newUser._id)

		res.status(201).json({ status: 'success', data: { user: newUser } })
	} catch (err) {
		res.status(400).json({ status: 'fail', message: err })
	}
}

exports.login = async (req, res, next) => {
	try {
		const { email, password } = req.body

		if (!email || !password) {
			return res
				.status(400)
				.json({ status: 'fail', message: 'Please provide email and password' })
		}

		const user = await User.findOne({ email }).select('+password')

		if (!user || !(await user.correctPassword(password, user.password))) {
			return res
				.status(401)
				.json({ status: 'fail', message: 'Incorrect email or password' })
		}

		const token = signToken(user._id)
    
    res.status(200).json({ status: 'success', token })
	} catch (err) {
		res.status(400).json({ status: 'fail', message: err })
	}
}
