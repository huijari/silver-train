import * as crypto from 'crypto'

export function generateKeyAndSignature(
	password: string,
	saltString?: string
): [Buffer, string, Buffer] {
	let salt
	if (saltString == undefined) salt = crypto.randomBytes(16)
	else salt = Buffer.from(saltString, 'base64')

	const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256')
	const hmac = crypto.createHmac('sha256', key)
	hmac.update(salt)
	const sign = hmac.digest('base64')

	return [key, sign, salt]
}

export function encrypt(key: Buffer, raw: string) {
	const iv = crypto.randomBytes(16)
	let cipher = crypto.createCipheriv('aes256', key, iv)
	const ciphertext = Buffer.concat([cipher.update(raw), cipher.final()])
	return [ciphertext.toString('base64'), iv.toString('base64')]
}

export function decrypt(key: Buffer, ivString: string, ciphertext: string) {
	const iv = Buffer.from(ivString, 'base64')
	const decipher = crypto.createDecipheriv('aes256', key, iv)
	const raw = Buffer.concat([
		decipher.update(Buffer.from(ciphertext, 'base64')),
		decipher.final(),
	]).toString()
	return raw
}
