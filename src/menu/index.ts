import Conf from 'conf'
import { prompt } from 'enquirer'
import * as crypto from 'crypto'

import { Account } from '../account'
import myAccounts from './myAccounts'
import importFromBrowser from './importFromBrowser'
import changeMasterPassword from './changeMasterPassword'

function getAccountsWithDuplicatePasswords(
	key: Buffer,
	accounts: Account[]
): string[] {
	let counter: { [key: string]: [number, string] } = {}
	let duplicateAccounts: string[] = []
	accounts.forEach((acc) => {
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

async function menu(config: Conf, key: Buffer) {
	const accounts = (config.get('accounts') ?? []) as Account[]
	const duplicates = getAccountsWithDuplicatePasswords(key, accounts)
	if (duplicates.length) {
		console.warn(
			`\x1b[33mWARNING: \x1b[0mYou have accounts with duplicate passwords: \n- ${duplicates.join(
				'\n- '
			)}`
		)
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
			await myAccounts(config, accounts, key)
			return true
		}
		case 'import from browser': {
			await importFromBrowser(config, key)
			return true
		}
		case 'change master password': {
			await changeMasterPassword(config, key)
			return true
		}
		case 'exit': {
			return false
		}
	}
	return true
}

export default menu
