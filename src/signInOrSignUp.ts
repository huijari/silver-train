import Conf from 'conf/dist/source'
import { prompt } from 'enquirer'
import * as crypto from 'crypto'

function signIn(config: Conf, password: string) {
	const salt = Buffer.from(config.get('salt') as string, 'base64')
	const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256')

	const hmac = crypto.createHmac('sha256', key)
	hmac.update(salt)
	const sign = hmac.digest('base64')

	if (sign !== config.get('sign')) {
		console.log('invalid password')
		return null
	} else console.log('password ok')

	return key
}

function signUp(config: Conf, password: string) {
	const salt = crypto.randomBytes(16)
	const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256')

	const hmac = crypto.createHmac('sha256', key)
	hmac.update(salt)
	const sign = hmac.digest('base64')

	config.set({
		salt: salt.toString('base64'),
		sign,
	})

	console.log('setup complete')
	return key
}

async function signInOrSignUp(config: Conf) {
	const { password } = (await prompt({
		type: 'password',
		name: 'password',
		message: 'Master password',
	})) as { password: string }

	const hasAccount = config.has('salt') && config.has('sign')
	if (hasAccount) return signIn(config, password)
	return signUp(config, password)
}

export default signInOrSignUp
