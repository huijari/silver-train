# silver-train
offline password manager

> **Warning**  
> This is an experimental project developed for a software engineering class,
> there are no guarantees that cryptographic constructs are being used in a safe way

## Interaction summary
```
start
check database
  exists
    login
      ask for master password
      validate password
  doesn't exists
    setup
      ask for master password
      generate key
      create local database
select account
  list names with autocomplete
  exists
    choose between
      copy password
        write to clipboard
      edit account
        select field
        ask for new value
        update
      remove account
        confirm
      cancel
  doesn't exists
    insert account
      ask for login information
      encrypt password
      save
exit
```

## Cryptography
### key derivation
PBKDF2
- password: user input
- salt: stored salt
- iterations: 100000
- keylen: 256
- digest: SHA256
### password validation
HMAC(SHA256, key)(salt) == stored computation
### encryption
cipher(AES256, key, random 128bits iv, raw)
### decryption
decipher(AES256, key, stored iv, ciphertext)
