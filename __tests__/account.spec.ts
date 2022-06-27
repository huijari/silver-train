import { Account, BrowserAccount, encryptAccount, generateRandomPassword, getAccountsWithDuplicatePasswords, getAuthenticationCode, getDecryptedAccountPassword, importBrowserAccount, setAccount2FA } from '../src/account'
import { generateKeyAndSignature, encrypt, decrypt } from '../src/crypto'
import * as OTP from 'otpauth'

const masterPassword = "Master@Password"
const password = 'Password@123'
let key: Buffer
let sign: string
let salt: Buffer

beforeAll(() => 
    [key,sign,salt] = generateKeyAndSignature(masterPassword)
)

it('creates account with encrypted password', () => {
    const testAccount: Account = encryptAccount(key, 'new account', 'username', password)
    expect(decrypt(key, testAccount.iv, testAccount.password)).toEqual(password)
})

it('gets account password with right key', () => {
    const testAccount: Account = encryptAccount(key, 'new account', 'username', password)
    expect(getDecryptedAccountPassword(key, testAccount)).toEqual(password)
})

it('throws when getting account password with wrong key', () => {
    const [wrongKey] = generateKeyAndSignature(masterPassword)
    const testAccount: Account = encryptAccount(key, 'new account', 'username', password)
    expect(() => getDecryptedAccountPassword(wrongKey, testAccount)).toThrow()
})

it('sets account 2FA', () => {
    const testAccount: Account = encryptAccount(key, 'new account', 'username', password)
    const secret = "secret"
    const totp = new OTP.TOTP({ secret })
    const code = totp.generate()
    const twoFaAccount = setAccount2FA(key, secret, code, testAccount)
    expect(decrypt(key, twoFaAccount.otpIV, twoFaAccount.otpSecret)).toEqual(secret)
})

it('throws when setting 2FA with wrong code', () => {
    const testAccount: Account = encryptAccount(key, 'new account', 'username', password)
    const secret = "secret"
    const code = "Wrong code"
    expect(() => setAccount2FA(key, secret, code, testAccount)).toThrow()
})

it('gets account authentication code with right key', () => {
    const testAccount: Account = encryptAccount(key, 'new account', 'username', password)
    const secret = "secret"
    const totp = new OTP.TOTP({ secret })
    const code = totp.generate()
    const twoFaAccount = setAccount2FA(key, secret, code, testAccount)
    expect(getAuthenticationCode(key, twoFaAccount)).toEqual(code)
})

it('throws when getting account authentication code with wrong key', () => {
    const [wrongKey] = generateKeyAndSignature(masterPassword)
    const testAccount: Account = encryptAccount(key, 'new account', 'username', password)
    const secret = "secret"
    const totp = new OTP.TOTP({ secret })
    const code = totp.generate()
    const twoFaAccount = setAccount2FA(key, secret, code, testAccount)
    expect(() => getAuthenticationCode(wrongKey, twoFaAccount)).toThrow()
})

it('generates password with defined length', () => {
    const length = 22
    const newPassword = generateRandomPassword({
        includeSymbols: false,
        length: length
    })
    expect(newPassword.length).toEqual(length)
})

it('generates password with symbols', () => {
    const newPassword = generateRandomPassword({
        includeSymbols: true,
        length: 13
    })
    expect(newPassword).toMatch(/[!@#$%^&*()]/i)
})

it('generates password without symbols', () => {
    const newPassword = generateRandomPassword({
        includeSymbols: false,
        length: 13
    })
    expect(newPassword).not.toMatch(/[!@#$%^&*()]/i)
})

it('detects accounts with duplicate passwords', () => {
    const accounts = [encryptAccount(key, 'account 1', 'username', password), encryptAccount(key, 'account 2', 'username', password)]
    expect(getAccountsWithDuplicatePasswords(key, accounts)).toContainEqual('account 1')
    expect(getAccountsWithDuplicatePasswords(key, accounts)).toContainEqual('account 2')
})

it('imports browser accounts with encrypted password', () => {
    const browserAcc: BrowserAccount = {
        url: "www.google.com",
        username: "test account",
        password: password
    }
    const newAccount = importBrowserAccount(key, browserAcc)
    expect(decrypt(key, newAccount.iv, newAccount.password)).toEqual(browserAcc.password)
})

it('imports browser accounts with user defined prefix', () => {
    const prefix = "[FireFox]"
    const browserAcc: BrowserAccount = {
        url: "www.google.com",
        username: "test account",
        password: password
    }
    const newAccount = importBrowserAccount(key, browserAcc, prefix)
    expect(newAccount.name).toMatch(new RegExp(`${prefix}.+`))
})