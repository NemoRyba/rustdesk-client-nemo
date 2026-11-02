# TBFDesk Android release signing

Every TBFDesk APK is signed with one private key. Android installs an update only if
it is signed with the **same** key as the app already on the phone.

- **Lose the key** and no phone can ever receive an update again: every user has to
  uninstall TBFDesk (losing its settings and ID config) and install a newly signed build.
- **Leak the key** and anyone can build an APK that phones accept as a "TBFDesk update".

So the key is created once, kept offline, and never enters git, a build server or a
shared drive in clear.

The application id is set in `gradle.properties` (`tbfdesk.applicationId`, currently
`at.tbf.tbfdesk`). Like the key, it is permanent once the first release is installed.

## 1. Create the key (once)

On a trusted machine (JDK `keytool`):

```sh
keytool -genkeypair -v -keystore tbfdesk-release.jks -keyalg RSA -keysize 4096 \
        -validity 10000 -alias tbfdesk
```

`keytool` asks for a keystore password, a key password and the certificate name
fields (CN = `TBF GmbH`, etc.). Use long random passwords and store them in the
password manager, not next to the file.

Record the certificate fingerprint; it identifies genuine TBFDesk builds:

```sh
keytool -list -v -keystore tbfdesk-release.jks -alias tbfdesk | grep SHA256
```

## 2. Keep it offline

- Two encrypted copies on two separate offline media (e.g. two encrypted USB sticks
  in two different places). Test that both copies open before relying on them.
- Passwords in the password manager; the file and the passwords are never stored
  together in clear.
- Never commit it. `*.jks`, `*.keystore` and `key.properties` are in
  `flutter/android/.gitignore`; check `git status` before every commit anyway.
- Never put it on the build server or into CI secrets. Release builds are signed on
  a trusted machine, the keystore is mounted only for the build and removed after.

## 3. Point the build at the key

Create `flutter/android/key.properties` (ignored by git) on the signing machine:

```properties
storeFile=/absolute/path/to/tbfdesk-release.jks
storePassword=...
keyAlias=tbfdesk
keyPassword=...
```

Use an absolute `storeFile` path (a relative one is resolved from
`flutter/android/app/`). `app/build.gradle` reads this file into
`signingConfigs.release`; without it a release build stops at
`validateSigningRelease` ("Keystore file not set") instead of using another key.
Delete `key.properties` again after the build.

## 4. Build a signed release APK

The Rust library must be built first and copied as
`app/src/main/jniLibs/<abi>/librustdesk.so` (see `flutter/build_fdroid.sh` or the
Android job in `.github/workflows/flutter-build.yml`; for arm64 also copy the NDK's
`libc++_shared.so`). Then, from `flutter/`:

```sh
flutter build apk --release --target-platform android-arm64 --split-per-abi
# output: build/app/outputs/flutter-apk/app-arm64-v8a-release.apk
```

Check the signature before distributing:

```sh
apksigner verify --print-certs build/app/outputs/flutter-apk/app-arm64-v8a-release.apk
```

The SHA-256 digest must match the fingerprint recorded in step 1.

Do not use the upstream GitHub workflows for releases: they `sed` the build to
`signingConfigs.debug`, which produces APKs signed with a throwaway debug key.

## 5. Google Play (if ever used)

With Play App Signing, Google holds the app signing key and TBF signs uploads with a
separate upload key (recoverable through Google if lost). The key above can be used
as that upload key, or enrolled as the app key. Private APK distribution (the current
plan) has no such safety net: the offline copies are the only recovery.
