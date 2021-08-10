test.apex is copied from ADBD apex built in AOSP.

```sh
$ apksigner verify -v test.apex
Verifies
Verified using v1 scheme (JAR signing): false
Verified using v2 scheme (APK Signature Scheme v2): false
Verified using v3 scheme (APK Signature Scheme v3): true
Verified using v4 scheme (APK Signature Scheme v4): false
Verified for SourceStamp: false
Number of signers: 1
```

Some test APKs are copied from tools/apksig/src/test/resources/com/android/apksig/.
- v3-only-cert-and-public-key-mismatch.apk
- v3-only-with-rsa-pkcs1-sha512-8192-digest-mismatch.apk
