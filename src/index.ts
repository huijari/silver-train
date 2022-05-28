import Conf from 'conf'
import { prompt } from 'enquirer'
import crypto from 'crypto'

const config = new Conf()

async function run() {
	if (config.has('salt') && config.has('sign')) console.log('database ok')
	else {
		const { password } = await prompt({
			type: 'password',
			name: 'password',
			message: 'Master password'
		}) as { password: string }

		const salt = crypto.randomBytes(16)
		const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256')

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

