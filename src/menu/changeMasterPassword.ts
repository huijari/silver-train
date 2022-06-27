import Conf from 'conf/dist/source'
import { prompt } from 'enquirer'
import * as crypto from 'crypto'

import { Account, getDecryptedAccountPassword } from '../account'
import { decrypt, encrypt } from '../crypto'

const recreateAccount = (key: Buffer, newKey: Buffer) => (account: Account) => {
	const password = getDecryptedAccountPassword(key, account)
	const [newPassword, newIV] = encrypt(newKey, password)
	account.iv = newIV
	account.password = newPassword

	if (account.otpSecret && account.otpIV) {
		const secret = decrypt(key, account.otpIV, account.otpSecret)
		const [newSecret, newOtpIV] = encrypt(newKey, secret)
		account.otpIV = newOtpIV
		account.otpSecret = newSecret
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
