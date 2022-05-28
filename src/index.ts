import Conf from 'conf'
import { prompt } from 'enquirer'
import * as crypto from 'crypto'

type Account = {
	name: string,
	username: string,
	password: string,
	iv: string
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
	if (accountName === 'new account') {
		const loginInformation: Account = await prompt([{
			type: 'input',
			name: 'name',
			message: 'Account name'
		}, {
			type: 'input',
			name: 'username',
			message: 'Username'
		}, {
			type: 'password',
			name: 'password',
			message: 'Password'
		}])

		const iv = crypto.randomBytes(16)
		const cipher = crypto.createCipheriv('aes256', key, iv)
		const password = Buffer.concat([
			cipher.update(loginInformation.password),
			cipher.final()
		])

		config.set('accounts', [
			...config.get('accounts', []) as Account[],
			{
				name: loginInformation.name,
				username: loginInformation.username,
				password: password.toString('base64'),
				iv: iv.toString('base64')
			}
		])
		console.log('account saved')
	} else {
		const account = (config.get('accounts') as Account[])
			.find(({ name }: Account) => name === accountName)!

		const { action } = await prompt({
			type: 'select',
			name: 'action',
			message: 'What do',
			choices: [
				'Copy password',
				'Remove',
				'Exit'
			]
		}) as { action: string }

		switch (action) {
			case 'Copy password': {
				const iv = Buffer.from(account.iv, 'base64')
				const ciphertext = Buffer.from(account.password, 'base64')
				const decipher = crypto.createDecipheriv('aes256', key, iv)
				const password = Buffer.concat([
					decipher.update(ciphertext),
					decipher.final()
				]).toString()
				const clipboard = await import('clipboardy')
				clipboard.default.writeSync(password)
				break
			}
			case 'Remove': {
				const { proceed } = await prompt({
					type: 'confirm',
					name: 'proceed',
					message: 'Are you sure?'
				}) as { proceed: boolean }
				if (proceed) {
					const accounts = (config.get('accounts') as Account[])
						.filter(({ name }) => name !== account.name)
					config.set('accounts', accounts)
				}
				break
			}
			default: return
		}
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

