create an app that will do the following:
1. User will open the app and will see a text edit field where he can enter text.
2. After inserting the text the user will push a "Send" button where it will do the following:
  * Create an RSA key pair for encrypting the string with a 1024 bit size and encrypt the string (please decide on the right PKCS padding).
  * Create another RSA keypair for signing the encrypted string before sending it and attach the signature to the payload. Key should use digest of SHA256 and be used for signing and verifying the decrypted string.
  * Create a background task that will send local push notification to the device. Send the push only 15 seconds after the user closes the app and moves it to the background. The push will contain the encrypted string with its signature.
  * Device should receive the push when the app is in the background and the phone is locked and show a notification on the lockscreen.
  * Pushing the lockscreen notification will open the app and move to a new VC (with a back option). Once in the new fragment the user should be shown a biometric popup and only after approving the biometrics you should verify the signature from the payload you received, decrypt the string and show it on a label on screen.
3. Please acknowledge each step in a label on screen, e.g "Keypair created", "String encrypted", "String signed", "Timer created for 15 sec" etc. and the same in the new fragment for showing the string, e.g "signature verified", "String decrypted" etc.
4. You can use third party dependencies for communication, parsing etc. but must use the iOS native frameworks for the crypto stuff. 
5. Please put a disable/enable button on the first page for using the biometric (in case it's disabled it will not ask for biometric in the second page).
6. Please try to make the app look nice but only use the native UI components. No need to call any UI designer (-;
7. Make sure to keep concurrency and crash free. 
8. Make sure to add comments in the code for all the steps, keep the code clean and object oriented.
9. App should work on iOS 14 (will not be tested on lower versions).
