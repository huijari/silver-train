import Conf from 'conf'
import { prompt } from 'enquirer'
import crypto from 'crypto'

type Account = {
	name: string,
	username: string,
	password: string
}

const config = new Conf()

async function run(key: Buffer) {
	const names = ((config.get('accounts') as Account[]) ?? []).map(({ name }: Account) => name)
	const { accountName } = await prompt({
		type: 'autocomplete',
		name: 'accountName',
		message: 'Choose an account',
    choices: [ 'new account', ...names ]
	}) as { accountName: string }
	if (accountName === 'new account') console.log('new account')
	else {
		const account = (config.get('accounts') as Account[])
			.find(({ name }: Account) => name === accountName)
		console.log(account)
	}
}

async function init() {
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

		if (sign !== config.get('sign')) return console.log('invalid password')
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

	run(key)
}

init()

