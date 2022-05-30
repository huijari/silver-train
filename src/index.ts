import Conf from 'conf'

import signInOrSignUp from './signInOrSignUp'
import menu from './menu/index'

async function run() {
	const config = new Conf()
	let key = await signInOrSignUp(config)
	if (key !== null) while (key = await menu(config, key)) { }
}

run()
