import Conf from 'conf/dist/source'
import { prompt } from 'enquirer'

import { generateKeyAndSignature } from './crypto'

function signIn(config: Conf, password: string) {
	const [key, sign] = generateKeyAndSignature(
		password,
		config.get('salt') as string
	)
	if (sign !== config.get('sign')) {
		console.log('invalid password')
		return null
	} else {
		console.log('password ok')
		return key
	}
}

function signUp(config: Conf, password: string) {
	const [key, sign, salt] = generateKeyAndSignature(password)
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
