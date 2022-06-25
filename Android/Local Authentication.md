## Testing Confirm Credentials
- Does the app ensure the user has set lock screen pin?
- Is the app using a big time window since last unlocked ?
- is the unlocked key used during the application flow ?
	- if not a local authenication bypass maybe possible

## Testing Biometric Authentication
- Check for keywords `BiometricManager`, `BiometricPrompt` and `FingerprintManager` (Deprecated )
- is it used on it 's own ?
	- is it generating a key and saving it in AndroidKeyStore? and retrieving it to get the data

##  Testing FingerprintManager
#### Make Sure the following is checked
- permission set in the AndroidManifest.xml
	```xml
	<uses-permission
	android:name="android.permission.USE_FINGERPRINT" />
	```
- Fingerprint hardware availability
- protected lock screen set 
- At least one finger should be registered
- application should have permission to ask for a user fingerprint
	 `context.checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PermissionResult.PERMISSION_GRANTED;`
- key resides inside secure hardware	 
	```Java
	SecretKeyFactory factory = SecretKeyFactory.getInstance(getEncryptionKey().getAlgorithm(), ANDROID_KEYSTORE);
	KeyInfo secetkeyInfo = (KeyInfo) factory.getKeySpec(yourencryptionkeyhere, KeyInfo.class);
	secetkeyInfo.isInsideSecureHardware()
	```
- 