# Secure Storage Abstraction

Core defines the SecureStorage interface because it owns how identities are saved. The app implements it through UniFFI, such as with Keychain or Keystore, so Core never calls platform APIs.
