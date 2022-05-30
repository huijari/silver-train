# silver-train
Offline password manager

> **Warning**  
> This is an experimental project developed for a software engineering class,
> there are no guarantees that cryptographic constructs are being used in a safe way

## Integrantes:
- Alexandre Cesar da Silva
- Marcos Carvalho de Assis

## Explicação do Sistema:
Gerenciador de senhas com interface de linha de comando, incluindo as seguintes funcionalidades:
  - Armazenamento de senhas criptografadas com a função de derivação de chave PBKDF2, algoritmo de hash SHA256 e padrão AES256.
  - Gerenciamento de senhas fixas e One-Time Passwords (OTP)
  - Geração de senhas "fortes" automaticamente
  - Importação de arquivos de senhas exportadas de navegadores Web
  - Detecção de senhas duplicadas entre as armazenadas

## Tecnologias utilizadas:
- Feito em Typescript, para ser executado por Node.js
- Interface de linha de comando [enquirer](https://github.com/enquirer/enquirer)
- Funções de criptografia disponíveis no módulo incluído de Node.js [crypto](https://nodejs.org/api/crypto.html)
- Senhas armazenadas no arquivo de configuração criado pelo pacote [conf](https://www.npmjs.com/package/conf)
- Gerenciamento de OTPs feito com o pacote [otpauth](https://www.npmjs.com/package/otpauth)
- Geração de senhas feita com o pacote [secure-random-password](https://www.npmjs.com/package/secure-random-password)
- Arquivos .csv exportados de navegadores são interpretados com o pacote [csv-parse](https://www.npmjs.com/package/csv-parse)
- A senha escolhida é copiada para a área de transferência com o pacote [clipboardy](https://www.npmjs.com/package/clipboardy)

## Utilização:
- `npm run build` - transpila o código Typescript para Javascript
- `node bin/index.js` - executa o código transpilado, no Node.js

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
