//.get(authMiddleware, userController.getUsers)   приклад використання
const jwt = require('jsonwebtoken')
const { promisify } = require('util')
const User = require('../models/User')
exports.authProtect = async (req, res, next) => {
	try {
		let token
		if (
			req.headers.authorization &&
			req.headers.authorization.startsWith('Bearer')
		) {
			const token = req.headers.authorization.split(' ')[1]
		}
		if (!token) {
			return res.status(401).json({
				status: 'fail',
				message: 'You are not logged in! Please log in to get access',
			})
		}

		const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET)

		const freshUser = await User.findById(decoded.id)
		if (!freshUser) {
			return next(
				res.status(401).json({
					status: 'fail',
					message: 'The user belonging to this token does no longer exist',
				})
			)
		}

    if( freshUser.changesPasswordAfter(decoded.iat)){
      return next(res.status(401).json({status: 'fail', message: 'User recently changed password! Please log in again'}))
    }
req.user = freshUser
		next()
	} catch (err) {
		res.status(400).json({ status: 'fail', message: err })
	}
}
