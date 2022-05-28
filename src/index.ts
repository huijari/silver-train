import Conf from 'conf'
import { prompt } from 'enquirer'
import crypto from 'crypto'

const config = new Conf()

async function run() {
	const { password } = await prompt({
		type: 'password',
		name: 'password',
		message: 'Master password'
	}) as { password: string }

	let key

	if (config.has('salt') && config.has('sign')) {
		const salt = Buffer.from(config.get('salt') as string, 'base64')
		key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256')

		const hmac = crypto.createHmac('sha256', key)
		hmac.update(salt)
		const sign = hmac.digest('base64')

		if (sign !== config.get('sign')) console.log('invalid password')
		else console.log('password ok')
	} else {
		const salt = crypto.randomBytes(16)
		key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256')

		const hmac = crypto.createHmac('sha256', key)
		hmac.update(salt)
		const sign = hmac.digest('base64')

		config.set({
			salt: salt.toString('base64'),
			sign
		})

		console.log('setup complete')
	}
}

run()

