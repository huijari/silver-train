import { encrypt, decrypt } from './crypto'

export type Account = {
	name: string
	username: string
	password: string
	iv: string
	otpSecret?: string
	otpIV?: string
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

export type PasswordGenerationParameters = {
	includeSymbols: boolean
	length: number
}

export function getDecryptedAccountPassword(
	key: Buffer,
	account: Account
): string {
	return decrypt(key, account.iv, account.password)
}


export function getAccountsWithDuplicatePasswords(
	key: Buffer,
	accounts: Account[]
): string[] {
	let duplicates: { [key: string]: string[] } = {}
	accounts.forEach((acc) => {
		const password = getDecryptedAccountPassword(key, acc)
		duplicates[password] = duplicates[password] ? [...duplicates[password], acc.name] : [acc.name]
	})
	return Object.values(duplicates).filter(arr => arr.length > 1).flat()
}

export function encryptAccount(key: Buffer, name: string, username: string, password: string ): Account {
	const [cipheredPassword, iv] = encrypt(key, password)
	return {
		name: name,
		username: username,
		password: cipheredPassword,
		iv: iv
	}
}

export function generateRandomPassword(params: PasswordGenerationParameters): string {
	const generator = require('secure-random-password')
	return generator.randomPassword({
		length: params.length,
		characters: [
			generator.lower,
			generator.upper,
			generator.digits,
		].concat(params.includeSymbols ? [generator.symbols] : []),
	})
}

export function importBrowserAccount(key: Buffer, browserAcc: BrowserAccount, prefix?: string) {
	let domain = browserAcc.url.match(/^(?:https?:\/\/)?(?:www.)?(.+)/i)?.[1]
	let suffix = browserAcc.username ? ` (${browserAcc.username})` : ''
	let name = `${prefix ?? ""}${domain}${suffix}`
	const [cipheredPassword, iv] = encrypt(key, browserAcc.password)
	return {
		name: name,
		username: browserAcc.username,
		password: cipheredPassword,
		iv: iv
	}
}