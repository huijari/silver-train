import Conf from 'conf'
import { prompt } from 'enquirer'

import { Account, getDecryptedAccountPassword, getAccountsWithDuplicatePasswords } from '../account'
import myAccounts from './myAccounts'
import importFromBrowser from './importFromBrowser'
import changeMasterPassword from './changeMasterPassword'

async function menu(config: Conf, key: Buffer): Promise<Buffer | null> {
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
			return key
		}
		case 'import from browser': {
			await importFromBrowser(config, key)
			return key
		}
		case 'change master password': {
			key = await changeMasterPassword(config, key)
			return key
		}
		case 'exit': {
			return null
		}
	}
	return key
}

export default menu
