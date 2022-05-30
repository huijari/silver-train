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
