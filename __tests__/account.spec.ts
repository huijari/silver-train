import { Account, BrowserAccount, encryptAccount, generateRandomPassword, getAccountsWithDuplicatePasswords, importBrowserAccount } from '../src/account'
import { generateKeyAndSignature, encrypt, decrypt } from '../src/crypto'

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