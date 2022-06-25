#### Identify encryption mechanisms
#### Keywords to look for
- `DES`, `AES`
- specifications for a key generator (like `KeyGenParameterSpec`, `KeyPairGeneratorSpec`, `KeyPairGenerator`, `KeyGenerator`, `KeyProperties`
- classes using `java.security.*`, `javax.crypto.*`, `android.security.*` and `android.security.keystore.*` packages

#### Check if symmetric keys are not:
-   part of application resources
-   values which can be derived from known values
-   hardcoded in code

***

#### Identify custom crypto implementations
##### Look for keywords
-   classes `Cipher`, `Mac`, `MessageDigest`, `Signature`
-   interfaces `Key`, `PrivateKey`, `PublicKey`, `SecretKey`
-   functions `getInstance`, `generateKey`
-   exceptions `KeyStoreException`, `CertificateException`, `NoSuchAlgorithmException`
-   classes which uses `java.security.*`, `javax.crypto.*`, `android.security.*` and `android.security.keystore.*` packages.

#### Look for calls
-  getInstance that don't use default `provider` of security services or null

***

### Identify crypto purposes
- encrypt/decrypt: ensures confidentiality of data
- sign/verify: ensures integrity of data
- maintance: protects key during an operation

***

### Testing Random Number Generators
- Is `Securerandom` always used for RNG generator
- Is the seed for the generator explicitily specified?
- Look for uses of `java.util.Random`

***


