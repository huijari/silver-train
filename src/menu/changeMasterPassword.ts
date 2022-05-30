import Conf from 'conf/dist/source'
import { prompt } from 'enquirer'
import * as crypto from 'crypto'

import { Account, getDecryptedAccountPassword } from '../account'

const recreateAccount = (key: Buffer, newKey: Buffer) => (account: Account) => {
	const password = getDecryptedAccountPassword(key, account)
	const newIV = crypto.randomBytes(16)
	let cipher = crypto.createCipheriv('aes256', newKey, newIV)
	const newPassword = Buffer.concat([cipher.update(password), cipher.final()])

	account.iv = newIV.toString('base64')
	account.password = newPassword.toString('base64')

	if (account.otpSecret !== undefined) {
		const otpIV = Buffer.from(account.otpIV, 'base64')
		const secretCipher = Buffer.from(account.otpSecret, 'base64')
		const decipher = crypto.createDecipheriv('aes256', key, otpIV)
		const secret = Buffer.concat([
			decipher.update(secretCipher),
			decipher.final(),
		]).toString()

		const newOtpIV = crypto.randomBytes(16)
		cipher = crypto.createCipheriv('aes256', newKey, newOtpIV)
		const newSecret = Buffer.concat([cipher.update(secret), cipher.final()])

		account.otpIV = newOtpIV.toString('base64')
		account.otpSecret = newSecret.toString('base64')

	}
	return account
}

async function action(config: Conf, key: Buffer): Promise<Buffer> {
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

	const accounts = ((config.get('accounts') ?? []) as Account[]).map(
		recreateAccount(key, newKey)
	)

	config.set({
		salt: salt.toString('base64'),
		sign,
		accounts,
	})
	return newKey
}

export default action
