import Conf from 'conf'
import { prompt } from 'enquirer'
import * as crypto from 'crypto'

import { Account, BrowserAccount } from '../account'

async function action(config: Conf, key: Buffer) {
	const { filename } = (await prompt({
		type: 'input',
		name: 'filename',
		message: 'What file',
	})) as { filename: string }
	try {
		const content = (await import('fs')).readFileSync(filename, 'utf8')
		const browserAccounts = (await import('csv-parse/sync')).parse(content, {
			columns: true,
			skip_empty_lines: true,
			delimiter: ',',
		}) as BrowserAccount[]
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
		console.error(`Could not import accounts from ${filename}: ${e.message}`)
	}
}

export default action
