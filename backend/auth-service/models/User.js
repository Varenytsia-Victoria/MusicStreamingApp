const mongoose = require('mongoose')
const validator = require('validator')
const bcrypt = require('bcryptjs')

const userSchema = new mongoose.Schema({
	name: {
		type: string,
	},
	email: {
		type: string,
		required: [true, 'Please provide an email'],
		unique: true,
		lowercase: true,
		validate: [validator.isEmail, 'Please provide a valid email'],
	},
	password: {
		type: string,
		required: [true, 'Please provide a password'],
		minlength: [6, 'Password must be at least 6 characters long'],
	},
	passwordConfirm: {
		type: string,
		required: [true, 'Please confirm your password'],
		validate: {
			validator: function (el) {
				return el === this.password
			},
			message: 'Passwords are not the same',
		},
	},
  passwordChangedAt: Date, 
})

userSchema.pre('save', async function (next) {
	if (!this.isModified('password')) return next()

	this.password = await bcrypt.hash(this.password, 12)

	this.passwordConfirm = undefined
})

userSchema.methods.correctPassword = async function (
	candidatePassword,
	userPassword
) {
	return await bcrypt.compare(candidatePassword, userPassword)
}

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
	if (this.passwordChangedAt) {
		const changedTimestamp = parseInt(
			this.passwordChangedAt.getTime() / 1000,
			10
		)
		return JWTTimestamp < changedTimestamp
	}
	return false
}

const User = mongoose.model('User', userSchema)

module.exports = User
