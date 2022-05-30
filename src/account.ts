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
