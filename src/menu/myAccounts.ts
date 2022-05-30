import Conf from 'conf'
import { prompt } from 'enquirer'
import * as crypto from 'crypto'
import * as OTP from 'otpauth'

import { Account } from '../account'

type PasswordGenerationParameters = {
	includeSymbols: boolean
	length: number
}

function generateRandomNumberInInterval(min: number, max: number) {
	return Math.floor(Math.random() * (max - min + 1) + min)
}

const nameLens = ({ name }: Account) => name
const namePredicate =
	(target: string) =>
	({ name }: Account) =>
		name === target
const nameNotPredicate =
	(target: string) =>
	({ name }: Account) =>
		name !== target
const setName = (target: string, name: string) => (account: Account) => {
	if (account.name === target) return { ...account, name }
	return account
}
const setUsername =
	(target: string, username: string) => (account: Account) => {
		if (account.name === target) return { ...account, username }
		return account
	}
const setPassword =
	(target: string, password: string, iv: string) => (account: Account) => {
		if (account.name === target) return { ...account, password, iv }
		return account
	}
const setOtp =
	(target: string, otpSecret: string, otpIV: string) => (account: Account) => {
		if (account.name === target) return { ...account, otpSecret, otpIV }
		return account
	}

async function action(config: Conf, accounts: Account[], key: Buffer) {
	const names = accounts.map(nameLens)
	const { accountName } = (await prompt({
		type: 'autocomplete',
		name: 'accountName',
		message: 'Choose an account',
		choices: ['new account', ...names, 'exit'],
	})) as { accountName: string }
	if (accountName === 'new account') {
		let loginInformation: Account = await prompt([
			{
				type: 'input',
				name: 'name',
				message: 'Account name',
			},
			{
				type: 'input',
				name: 'username',
				message: 'Username',
			},
			{
				type: 'password',
				name: 'password',
				message: 'Password - leave it blank for automatic password generation',
			},
		])

		const iv = crypto.randomBytes(16)
		const cipher = crypto.createCipheriv('aes256', key, iv)

		if (!loginInformation.password) {
			const generator = require('secure-random-password')
			const parameters: PasswordGenerationParameters = (await prompt([
				{
					type: 'confirm',
					name: 'includeSymbols',
					message: 'Include special characters?',
					initial: true,
				},
				{
					type: 'numeral',
					name: 'length',
					message: 'Length of the password',
					initial: generateRandomNumberInInterval(12, 16),
				},
			])) as PasswordGenerationParameters
			loginInformation.password = generator.randomPassword({
				length: parameters.length,
				characters: [generator.lower, generator.upper, generator.digits].concat(
					parameters.includeSymbols ? [generator.symbols] : []
				),
			})
		}

		const password = Buffer.concat([
			cipher.update(loginInformation.password),
			cipher.final(),
		])

		config.set('accounts', [
			...(config.get('accounts', []) as Account[]),
			{
				name: loginInformation.name,
				username: loginInformation.username,
				password: password.toString('base64'),
				iv: iv.toString('base64'),
			},
		])
		console.log('account saved')
	} else if (accountName === 'exit') {
		return false
	} else {
		const account = (config.get('accounts') as Account[]).find(
			namePredicate(accountName)
		)!

		const { action } = (await prompt({
			type: 'select',
			name: 'action',
			message: 'What do',
			choices: [
				'Copy password',
				...(account.otpSecret !== undefined
					? ['Copy authentication code']
					: []),
				'Edit account',
				'Remove',
				'Exit',
			],
		})) as { action: string }

		switch (action) {
			case 'Copy password': {
				const iv = Buffer.from(account.iv, 'base64')
				const ciphertext = Buffer.from(account.password, 'base64')
				const decipher = crypto.createDecipheriv('aes256', key, iv)
				const password = Buffer.concat([
					decipher.update(ciphertext),
					decipher.final(),
				]).toString()
				const clipboard = await import('clipboardy')
				clipboard.default.writeSync(password)
				break
			}
			case 'Copy authentication code': {
				const iv = Buffer.from(account.otpIV, 'base64')
				const ciphertext = Buffer.from(account.otpSecret, 'base64')
				const decipher = crypto.createDecipheriv('aes256', key, iv)
				const secret = Buffer.concat([
					decipher.update(ciphertext),
					decipher.final(),
				]).toString()
				const code = new OTP.TOTP({ secret }).generate()
				const clipboard = await import('clipboardy')
				clipboard.default.writeSync(code)
				console.log(code)
				break
			}
			case 'Edit account': {
				const { field } = (await prompt({
					type: 'select',
					name: 'field',
					message: 'What edit',
					choices: ['name', 'username', 'password', '2fa', 'nevermind'],
				})) as { field: string }
				switch (field) {
					case 'name': {
						const { newName } = (await prompt([
							{
								type: 'input',
								name: 'newName',
								message: `New account name for '${account.name}'`,
							},
						])) as { newName: string }
						config.set(
							'accounts',
							(config.get('accounts') as Account[]).map(
								setName(account.name, newName)
							)
						)
						break
					}
					case 'username': {
						const { newUsername } = (await prompt([
							{
								type: 'input',
								name: 'newUsername',
								message: `New username for '${account.name}'`,
							},
						])) as { newUsername: string }
						config.set(
							'accounts',
							(config.get('accounts') as Account[]).map(
								setUsername(account.name, newUsername)
							)
						)
						break
					}
					case 'password': {
						let { newPassword } = (await prompt([
							{
								type: 'password',
								name: 'newPassword',
								message: `New password for '${account.name}' - leave it blank for automatic password generation`,
							},
						])) as { newPassword: string }
						const iv = crypto.randomBytes(16)
						const cipher = crypto.createCipheriv('aes256', key, iv)
						if (!newPassword) {
							const generator = require('secure-random-password')
							const parameters: PasswordGenerationParameters = (await prompt([
								{
									type: 'confirm',
									name: 'includeSymbols',
									message: 'Include special characters?',
									initial: true,
								},
								{
									type: 'numeral',
									name: 'length',
									message: 'Length of the password',
									initial: generateRandomNumberInInterval(12, 16),
								},
							])) as PasswordGenerationParameters
							newPassword = generator.randomPassword({
								length: parameters.length,
								characters: [
									generator.lower,
									generator.upper,
									generator.digits,
								].concat(parameters.includeSymbols ? [generator.symbols] : []),
							})
						}
						const newPasswordCipher = Buffer.concat([
							cipher.update(newPassword),
							cipher.final(),
						])
						config.set(
							'accounts',
							(config.get('accounts') as Account[]).map(
								setPassword(
									account.name,
									newPasswordCipher.toString('base64'),
									iv.toString('base64')
								)
							)
						)
						break
					}
					case '2fa': {
						const { secret } = (await prompt([
							{
								type: 'password',
								name: 'secret',
								message: `2FA secret for '${account.name}'`,
							},
						])) as { secret: string }
						const totp = new OTP.TOTP({ secret })
						const { code } = (await prompt([
							{
								type: 'input',
								name: 'code',
								message: 'Authentication code',
							},
						])) as { code: string }
						if (totp.generate() !== code)
							console.log('Invalid authentication code')
						else {
							const iv = crypto.randomBytes(16)
							const cipher = crypto.createCipheriv('aes256', key, iv)
							const otpSecret = Buffer.concat([
								cipher.update(secret),
								cipher.final(),
							])
							config.set(
								'accounts',
								(config.get('accounts') as Account[]).map(
									setOtp(
										account.name,
										otpSecret.toString('base64'),
										iv.toString('base64')
									)
								)
							)
						}
					}
				}
				break
			}
			case 'Remove': {
				const { proceed } = (await prompt({
					type: 'confirm',
					name: 'proceed',
					message: 'Are you sure?',
				})) as { proceed: boolean }
				if (proceed) {
					const accounts = (config.get('accounts') as Account[]).filter(
						nameNotPredicate(account.name)
					)
					config.set('accounts', accounts)
				}
				break
			}
			case 'Exit': {
				return false
			}
			default:
				return
		}
	}
}

export default action
