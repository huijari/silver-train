import Conf from 'conf'
import { prompt } from 'enquirer'
import * as crypto from 'crypto'
import * as OTP from 'otpauth'
import internal from 'stream'

type Account = {
	name: string
	username: string
	password: string
	iv: string
	otpSecret: string
	otpIV: string
}

type BrowserAccount = {
	url: string
	username: string
	password: string
	httpRealm?: string
	formActionOrigin?: string
	guid?: string
	timeCreated?: string
	timeLastUsed?: string
	timePasswordChanged?: string
}

type PasswordGenerationParameters = {
	includeSymbols: boolean
	length: number
}

function generateRandomNumberInInterval(min: number, max: number) {
	return Math.floor(Math.random() * (max - min + 1) + min)
}

function getAccountsWithDuplicatePasswords(key: Buffer, accounts: Account[]): string[] {
	let counter: { [key: string]: [number, string] } = {}
	let duplicateAccounts: string[] = []
	accounts.forEach(acc => {
		const iv = Buffer.from(acc.iv, 'base64')
		const ciphertext = Buffer.from(acc.password, 'base64')
		const decipher = crypto.createDecipheriv('aes256', key, iv)
		const password = Buffer.concat([
			decipher.update(ciphertext),
			decipher.final(),
		]).toString()
		if (counter[password]) {
			if (counter[password][0] === 1) {
				duplicateAccounts.push(counter[password][1])
			}
			duplicateAccounts.push(acc.name)
			counter[password][0]++
		} else {
			counter[password] = [1, acc.name]
		}
	})
	return duplicateAccounts
}

const config = new Conf()

async function run(key: Buffer) {
	const accounts = (config.get('accounts') ?? []) as Account[]
	const duplicates = getAccountsWithDuplicatePasswords(key, accounts)
	if (duplicates.length) {
		console.warn(`\x1b[33mWARNING: \x1b[0mYou have accounts with duplicate passwords: \n- ${duplicates.join('\n- ')}`)
	}
	const { action } = (await prompt({
		type: 'select',
		name: 'action',
		message: "Silver train is a comin'",
		choices: [
			'my accounts',
			'import from browser',
			'change master password',
			'exit',
		],
	})) as { action: string }
	switch (action) {
		case 'my accounts': {
			const names = accounts.map(
				({ name }: Account) => name
			)
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
						message:
							'Password - leave it blank for automatic password generation',
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
						characters: [
							generator.lower,
							generator.upper,
							generator.digits,
						].concat(parameters.includeSymbols ? [generator.symbols] : []),
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
					({ name }: Account) => name === accountName
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
									(config.get('accounts') as Account[]).map((acc) =>
										acc.name === account.name ? { ...acc, name: newName } : acc
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
									(config.get('accounts') as Account[]).map((acc) =>
										acc.name === account.name
											? { ...acc, username: newUsername }
											: acc
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
									const parameters: PasswordGenerationParameters =
										(await prompt([
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
										].concat(
											parameters.includeSymbols ? [generator.symbols] : []
										),
									})
								}
								const newPasswordCipher = Buffer.concat([
									cipher.update(newPassword),
									cipher.final(),
								])
								config.set(
									'accounts',
									(config.get('accounts') as Account[]).map((acc) =>
										acc.name === account.name
											? {
													...acc,
													password: newPasswordCipher.toString('base64'),
													iv: iv.toString('base64'),
											  }
											: acc
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
										(config.get('accounts') as Account[]).map((acc) =>
											acc.name === account.name
												? {
														...acc,
														otpSecret: otpSecret.toString('base64'),
														otpIV: iv.toString('base64'),
												  }
												: acc
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
								({ name }) => name !== account.name
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
			return true
		}
		case 'import from browser': {
			const { filename } = (await prompt({
				type: 'input',
				name: 'filename',
				message: 'What file',
			})) as { filename: string }
			try {
				const content = (await import('fs')).readFileSync(filename, 'utf8')
				const browserAccounts = (await import('csv-parse/sync')).parse(
					content,
					{
						columns: true,
						skip_empty_lines: true,
						delimiter: ',',
					}
				) as BrowserAccount[]
				const { prefix } = (await prompt({
					type: 'input',
					name: 'prefix',
					message: 'Want to add a prefix for the imported accounts?',
				})) as { prefix: string }
				const importedAccounts = browserAccounts.map((acc) => {
					let iv = crypto.randomBytes(16)
					let cipher = crypto.createCipheriv('aes256', key, iv)
					let password = Buffer.concat([
						cipher.update(acc.password),
						cipher.final(),
					])
					let domain = acc.url.match(/^(?:https?:\/\/)?(?:www.)?(.+)/i)?.[1]
					let suffix = acc.username ? ` (${acc.username})` : ''
					let name = `${prefix}${domain}${suffix}`
					return {
						name: name,
						username: acc.username,
						password: password.toString('base64'),
						iv: iv.toString('base64'),
					}
				}) as Account[]
				config.set('accounts', [
					...(config.get('accounts', []) as Account[]),
					...importedAccounts,
				])
				console.log('Accounts imported successfully')
			} catch (e: any) {
				console.error(
					`Could not import accounts from ${filename}: ${e.message}`
				)
			}
			return true
		}
		case 'change master password': {
			const { password } = (await prompt({
				type: 'password',
				name: 'password',
				message: 'New password',
			})) as { password: string }

			const salt = crypto.randomBytes(16)
			const newKey = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256')

			const hmac = crypto.createHmac('sha256', newKey)
			hmac.update(salt)
			const sign = hmac.digest('base64')

			const accounts = (config.get('accounts') as Account[]).map((account) => {
				const iv = Buffer.from(account.iv, 'base64')
				const passwordCipher = Buffer.from(account.password, 'base64')
				let decipher = crypto.createDecipheriv('aes256', key, iv)
				const password = Buffer.concat([
					decipher.update(passwordCipher),
					decipher.final(),
				]).toString()

				const newIV = crypto.randomBytes(16)
				let cipher = crypto.createCipheriv('aes256', newKey, newIV)
				const newPassword = Buffer.concat([
					cipher.update(password),
					cipher.final(),
				])

				account.iv = newIV.toString('base64')
				account.password = newPassword.toString('base64')

				if (account.otpSecret !== undefined) {
					const otpIV = Buffer.from(account.otpIV, 'base64')
					const secretCipher = Buffer.from(account.otpSecret, 'base64')
					decipher = crypto.createDecipheriv('aes256', key, otpIV)
					const secret = Buffer.concat([
						decipher.update(secretCipher),
						decipher.final(),
					]).toString()

					const newOtpIV = crypto.randomBytes(16)
					cipher = crypto.createCipheriv('aes256', newKey, newOtpIV)
					const newSecret = Buffer.concat([
						cipher.update(secret),
						cipher.final(),
					])

					account.otpIV = newOtpIV.toString('base64')
					account.otpSecret = newSecret.toString('base64')

					return account
				}
			})

			config.set({
				salt: salt.toString('base64'),
				sign,
				accounts,
			})

			break
		}
		case 'exit': {
			return false
		}
	}
	return true
}

async function init() {
	const { password } = (await prompt({
		type: 'password',
		name: 'password',
		message: 'Master password',
	})) as { password: string }

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
			sign,
		})

		console.log('setup complete')
	}

	while (await run(key)) {}
}

init()
