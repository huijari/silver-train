import { generateKeyAndSignature, encrypt, decrypt } from '../src/crypto'

const masterPassword = "Master@Password"
const text_to_encrypt = "Text to encrypt"
let key: Buffer
let sign: string
let salt: Buffer

beforeAll(() => 
    [key,sign,salt] = generateKeyAndSignature(masterPassword)
)

it('does encrypt', () => {
    const [encrypted, iv] = encrypt(key, text_to_encrypt)
    expect(encrypted).not.toEqual(text_to_encrypt)
})

it('does decrypt', () => {
    const [encrypted, iv] = encrypt(key, text_to_encrypt)
    const decrypted = decrypt(key, iv, encrypted)
    expect(decrypted).toEqual(text_to_encrypt)
})

it('generates encrypted key', () => {
    expect(key).not.toEqual(masterPassword)
})

it('generates different keys', () => {
    const [diffKey] = generateKeyAndSignature(masterPassword)
    expect(diffKey).not.toEqual(key)
})

it('returns 16-byte iv', () => {
    const [encrypted, iv] = encrypt(key, text_to_encrypt)
    expect(Buffer.from(iv, 'base64').length).toBe(16)
})