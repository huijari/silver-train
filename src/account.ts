import * as crypto from 'crypto'

export type Account = {
	name: string
	username: string
	password: string
	iv: string
	otpSecret: string
	otpIV: string
}

export type BrowserAccount = {
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

export function getDecryptedAccountPassword(key: Buffer, account: Account): string {
	const iv = Buffer.from(account.iv, 'base64')
	const ciphertext = Buffer.from(account.password, 'base64')
	const decipher = crypto.createDecipheriv('aes256', key, iv)
	const password = Buffer.concat([
		decipher.update(ciphertext),
		decipher.final(),
	]).toString()
	return password
}