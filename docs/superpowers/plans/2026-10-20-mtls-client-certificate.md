# mTLS Client Certificate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional PKCS#12 client-certificate import and use it for mTLS with the configured tt-rss server, without changing username/password login.

**Architecture:** A new `org.fox.ttrss.mtls` package parses and stores the identity, owns a load/import/remove state machine, and supplies the current TLS context. `ApiCommon` and Glide select a plain or mTLS client per request. Storage is an AES/GCM blob in the no-backup directory.

**Tech Stack:** Java 17, Android minSdk 24, OkHttp 5.5, Glide 5.0.9, Android Keystore, JUnit 4, Mockito.

**Spec:** `docs/superpowers/specs/2026-10-20-mtls-client-certificate-design.md`

## Global Constraints

- Java only. Do not add Kotlin.
- Keep `minSdk 24`, `compileSdk 37`, and Java 17 source compatibility.
- Add no runtime dependency. Test-only dependencies are allowed only if they already exist.
- Use tabs with width 4 in Java. Use 4 spaces in Gradle.
- Add new user-visible text only to `org.fox.ttrss/src/main/res/values/strings.xml`.
- Never log a password, private key, certificate bytes, or decrypted payload.
- Keep server trust on Android's platform default trust manager. Do not add a permissive trust manager or hostname verifier.
- Run JVM tests with `./gradlew :org.fox.ttrss:testDebugUnitTest`.
- Run the full gate with `./gradlew --no-daemon check assembleDebug`.
- ErrorProne runs on main and test compilation. Build errors block the work.
- The Android SDK is at `/tmp/opencode/android-sdk`. `local.properties` points to it.

## Review Focus

These are the failure modes the plan's tests must pin:

1. A corrupt or undecryptable stored blob must never fall back to plain TLS. The manager returns `ERROR`. Task 3 test: `loadFailureFailsClosed`.
2. A failed import must keep the old `READY` snapshot. Task 3 test: `importFailureKeepsReadySnapshot`.
3. A cross-origin redirect must not receive the client certificate. API requests fail; images retry plain. Task 4 test: `crossOriginRedirectIsBlocked`; Task 5 test: `crossOriginRetryUsesPlainClient`.
4. Replace and remove must not reuse a pooled TLS connection with the old identity. Task 4 test: `clientChangesWithGeneration`.
5. A user-installed CA must still validate. Task 4 verification step confirms the trust manager comes from `TrustManagerFactory` with a null KeyStore. Manual check remains.

---

### Task 1: PKCS#12 Parsing and Payload Codec

**Files:**
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/ClientCertificate.java`
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/CertificateImportException.java`
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/ClientCertificateParser.java`
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/CertificatePayloadCodec.java`
- Create: `org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/ClientCertificateParserTest.java`
- Create: `org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/CertificatePayloadCodecTest.java`
- Create fixtures under `org.fox.ttrss/src/test/resources/mtls/`

**Interfaces:**
- Produces: `ClientCertificate(String displayName, String subject, long notAfterEpochMillis, String keyAlgorithm, PrivateKey privateKey, List<X509Certificate> chain)` with getters.
- Produces: `CertificateImportException.Reason { UNREADABLE, WRONG_PASSWORD, MISSING_KEY, MISSING_CHAIN, UNSUPPORTED_KEY, EXPIRED, NOT_YET_VALID }`.
- Produces: `static ClientCertificate ClientCertificateParser.parse(byte[] pkcs12, char[] password, String displayName, long nowEpochMillis) throws CertificateImportException`.
- Produces: `static byte[] CertificatePayloadCodec.encode(ClientCertificate certificate)`.
- Produces: `static ClientCertificate CertificatePayloadCodec.decode(byte[] payload) throws CertificateImportException`.

- [ ] **Step 1: Generate the committed fixtures**

Run these commands from the repository root:

```bash
mkdir -p org.fox.ttrss/src/test/resources/mtls
keytool -genkeypair -alias client -keyalg RSA -keysize 2048 -validity 3650 \
  -dname "CN=TT-RSS Test Client" -storetype PKCS12 \
  -keystore org.fox.ttrss/src/test/resources/mtls/client-rsa.p12 \
  -storepass testpass -keypass testpass
keytool -genkeypair -alias client -keyalg EC -groupname secp256r1 -validity 3650 \
  -dname "CN=TT-RSS EC Client" -storetype PKCS12 \
  -keystore org.fox.ttrss/src/test/resources/mtls/client-ec.p12 \
  -storepass testpass -keypass testpass
openssl req -x509 -newkey rsa:2048 -keyout /tmp/mtls-key.pem -out /tmp/mtls-cert.pem \
  -days 3650 -nodes -subj "/CN=TT-RSS Test Client"
openssl pkcs12 -export -out org.fox.ttrss/src/test/resources/mtls/client-nopass.p12 \
  -inkey /tmp/mtls-key.pem -in /tmp/mtls-cert.pem -passout pass:
openssl pkcs12 -export -nokeys -out org.fox.ttrss/src/test/resources/mtls/cert-only.p12 \
  -in /tmp/mtls-cert.pem -passout pass:testpass
```

Expected: four files exist in `src/test/resources/mtls/`. These are throwaway test keys.

- [ ] **Step 2: Write the failing parser test**

```java
package org.fox.ttrss.mtls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class ClientCertificateParserTest {

    private byte[] fixture(String name) throws Exception {
        try (InputStream in = getClass().getResourceAsStream("/mtls/" + name)) {
            assertNotNull(name, in);
            return in.readAllBytes();
        }
    }

    private long notAfterOf(byte[] p12, char[] password) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new java.io.ByteArrayInputStream(p12), password);
        Enumeration<String> aliases = store.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (store.isKeyEntry(alias)) {
                return ((X509Certificate) store.getCertificateChain(alias)[0]).getNotAfter().getTime();
            }
        }
        throw new AssertionError("no key entry");
    }

    @Test
    public void parsesRsaBundle() throws Exception {
        byte[] p12 = fixture("client-rsa.p12");
        ClientCertificate cert = ClientCertificateParser.parse(
                p12, "testpass".toCharArray(), "client-rsa.p12", System.currentTimeMillis());

        assertEquals("RSA", cert.getKeyAlgorithm());
        assertEquals("client-rsa.p12", cert.getDisplayName());
        assertEquals("CN=TT-RSS Test Client", cert.getSubject());
        assertNotNull(cert.getPrivateKey());
        assertEquals(1, cert.getChain().size());
    }

    @Test
    public void parsesEcBundle() throws Exception {
        ClientCertificate cert = ClientCertificateParser.parse(
                fixture("client-ec.p12"), "testpass".toCharArray(), "client-ec.p12",
                System.currentTimeMillis());

        assertEquals("EC", cert.getKeyAlgorithm());
        assertNotNull(cert.getPrivateKey());
    }

    @Test
    public void parsesEmptyPasswordBundle() throws Exception {
        ClientCertificate cert = ClientCertificateParser.parse(
                fixture("client-nopass.p12"), new char[0], "client-nopass.p12",
                System.currentTimeMillis());

        assertNotNull(cert.getPrivateKey());
    }

    @Test
    public void wrongPasswordHasTypedReason() throws Exception {
        try {
            ClientCertificateParser.parse(fixture("client-rsa.p12"), "wrong".toCharArray(),
                    "client-rsa.p12", System.currentTimeMillis());
            fail("expected failure");
        } catch (CertificateImportException e) {
            assertEquals(CertificateImportException.Reason.WRONG_PASSWORD, e.getReason());
        }
    }

    @Test
    public void corruptBytesAreUnreadable() {
        try {
            ClientCertificateParser.parse(new byte[]{1, 2, 3}, new char[0], "bad.p12",
                    System.currentTimeMillis());
            fail("expected failure");
        } catch (CertificateImportException e) {
            assertEquals(CertificateImportException.Reason.UNREADABLE, e.getReason());
        }
    }

    @Test
    public void certificateOnlyBundleHasNoKey() throws Exception {
        try {
            ClientCertificateParser.parse(fixture("cert-only.p12"), "testpass".toCharArray(),
                    "cert-only.p12", System.currentTimeMillis());
            fail("expected failure");
        } catch (CertificateImportException e) {
            assertEquals(CertificateImportException.Reason.MISSING_KEY, e.getReason());
        }
    }

    @Test
    public void expiredCertificateIsRejected() throws Exception {
        byte[] p12 = fixture("client-rsa.p12");
        long future = notAfterOf(p12, "testpass".toCharArray()) + 1000L;

        try {
            ClientCertificateParser.parse(p12, "testpass".toCharArray(), "client-rsa.p12", future);
            fail("expected failure");
        } catch (CertificateImportException e) {
            assertEquals(CertificateImportException.Reason.EXPIRED, e.getReason());
        }
    }
}
```

- [ ] **Step 3: Run the test and watch it fail**

```bash
./gradlew :org.fox.ttrss:testDebugUnitTest --tests "org.fox.ttrss.mtls.ClientCertificateParserTest"
```

Expected: compilation failure because the classes and methods do not exist.

- [ ] **Step 4: Implement the parser and exception**

`CertificateImportException` carries the `Reason` and an optional message/cause.

`ClientCertificateParser.parse`:
- Load `KeyStore.getInstance("PKCS12")` from the bytes. Treat `UnrecoverableKeyException` and a password-related `IOException` as `WRONG_PASSWORD`; other load failures as `UNREADABLE`.
- Iterate all aliases. Select the first `isKeyEntry` alias with a `PrivateKey` and a non-empty `X509Certificate` chain.
- Return `MISSING_KEY` when no key entry exists, `MISSING_CHAIN` when the chain is empty.
- Return `UNSUPPORTED_KEY` when the algorithm is not `RSA` or `EC`.
- Compare `notBefore` and `notAfter` with `nowEpochMillis` and return `NOT_YET_VALID` or `EXPIRED`.
- Use `leaf.getSubjectX500Principal().getName()` for the subject.
- Use the supplied display name, or the subject when the name is null/empty.

- [ ] **Step 5: Run the parser test to verify it passes**

Run the command from Step 3. Expected: all parser tests pass.

- [ ] **Step 6: Write the failing codec test**

```java
package org.fox.ttrss.mtls;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.io.InputStream;

public class CertificatePayloadCodecTest {

    private ClientCertificate sample() throws Exception {
        try (InputStream in = getClass().getResourceAsStream("/mtls/client-rsa.p12")) {
            assertNotNull(in);
            return ClientCertificateParser.parse(in.readAllBytes(), "testpass".toCharArray(),
                    "client-rsa.p12", System.currentTimeMillis());
        }
    }

    @Test
    public void roundTripsIdentity() throws Exception {
        ClientCertificate source = sample();
        ClientCertificate decoded = CertificatePayloadCodec.decode(
                CertificatePayloadCodec.encode(source));

        assertEquals(source.getDisplayName(), decoded.getDisplayName());
        assertEquals(source.getSubject(), decoded.getSubject());
        assertEquals(source.getNotAfterEpochMillis(), decoded.getNotAfterEpochMillis());
        assertEquals(source.getKeyAlgorithm(), decoded.getKeyAlgorithm());
        assertArrayEquals(source.getPrivateKey().getEncoded(),
                decoded.getPrivateKey().getEncoded());
        assertEquals(source.getChain().size(), decoded.getChain().size());
        assertArrayEquals(source.getChain().get(0).getEncoded(),
                decoded.getChain().get(0).getEncoded());
    }

    @Test
    public void unicodeDisplayNameRoundTrips() throws Exception {
        ClientCertificate source = sample();
        ClientCertificate named = new ClientCertificate("証明書.p12", source.getSubject(),
                source.getNotAfterEpochMillis(), source.getKeyAlgorithm(),
                source.getPrivateKey(), source.getChain());

        ClientCertificate decoded = CertificatePayloadCodec.decode(
                CertificatePayloadCodec.encode(named));

        assertEquals("証明書.p12", decoded.getDisplayName());
    }

    @Test
    public void rejectsWrongVersion() throws Exception {
        byte[] encoded = CertificatePayloadCodec.encode(sample());
        encoded[3] = 9;

        try {
            CertificatePayloadCodec.decode(encoded);
            fail("expected failure");
        } catch (CertificateImportException e) {
            assertEquals(CertificateImportException.Reason.UNREADABLE, e.getReason());
        }
    }

    @Test
    public void rejectsTruncatedPayload() throws Exception {
        try {
            CertificatePayloadCodec.decode(new byte[]{0, 0, 0, 1});
            fail("expected failure");
        } catch (CertificateImportException e) {
            assertEquals(CertificateImportException.Reason.UNREADABLE, e.getReason());
        }
    }

    @Test
    public void rejectsOversizedField() {
        byte[] payload = new byte[8];
        payload[3] = 1;
        payload[4] = 0x7f;
        payload[5] = (byte) 0xff;
        payload[6] = (byte) 0xff;
        payload[7] = (byte) 0xff;

        try {
            CertificatePayloadCodec.decode(payload);
            fail("expected failure");
        } catch (CertificateImportException e) {
            assertEquals(CertificateImportException.Reason.UNREADABLE, e.getReason());
        }
    }
}
```

- [ ] **Step 7: Run the codec test and watch it fail**

```bash
./gradlew :org.fox.ttrss:testDebugUnitTest --tests "org.fox.ttrss.mtls.CertificatePayloadCodecTest"
```

Expected: failure because `CertificatePayloadCodec` does not exist.

- [ ] **Step 8: Implement `CertificatePayloadCodec`**

Use `DataOutputStream` and `DataInputStream` with UTF-8 byte fields. Use this order: version `1`, display name, subject, `notAfter`, key algorithm, PKCS#8 bytes, chain count, each DER certificate. Read every length with a maximum: name and subject 4096, algorithm 64, key 65536, chain count 1..10, each certificate 65536, total 5 MB. Rebuild the key with `KeyFactory` and `PKCS8EncodedKeySpec`. Rebuild certificates with `CertificateFactory.getInstance("X.509")`. Map all parse failures to `CertificateImportException.Reason.UNREADABLE`.

- [ ] **Step 9: Run both test classes**

```bash
./gradlew :org.fox.ttrss:testDebugUnitTest --tests "org.fox.ttrss.mtls.*"
```

Expected: all tests pass.

- [ ] **Step 10: Commit**

```bash
git add org.fox.ttrss/src/main/java/org/fox/ttrss/mtls \
  org.fox.ttrss/src/test/java/org/fox/ttrss/mtls \
  org.fox.ttrss/src/test/resources/mtls
git commit -m "feat: parse and encode client certificates"
```

---

### Task 2: Encrypted Certificate Store

**Files:**
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/ClientCertificateStore.java`
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/StoreException.java`
- Create: `org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/ClientCertificateStoreTest.java`

**Interfaces:**
- Consumes: `ClientCertificate`, `CertificatePayloadCodec`, `CertificateImportException`.
- Produces: `interface ClientCertificateStore.CipherProvider { Cipher encryptCipher(byte[] iv, byte[] aad) throws GeneralSecurityException; Cipher decryptCipher(byte[] iv, byte[] aad) throws GeneralSecurityException; boolean deleteKey(); }`.
- Produces: `ClientCertificateStore(File directory, CipherProvider cipherProvider)`.
- Produces: `static ClientCertificateStore create(Context context)`.
- Produces: `boolean hasBlob()`.
- Produces: `ClientCertificate load() throws StoreException` (`null` when no blob).
- Produces: `void save(ClientCertificate certificate) throws StoreException`.
- Produces: `boolean clearFile()`.
- Produces: `boolean clearKey()`.
- Produces: `StoreException.Reason { IO, AUTH, KEY_MISSING, CORRUPT }`.

- [ ] **Step 1: Write the failing store test**

Use a temporary directory and a fixed AES key in the test:
- `encryptCipher` and `decryptCipher` initialize `AES/GCM/NoPadding` with a 12-byte IV, 128-bit tag, and AAD.
- `deleteKey` sets a flag.

Tests:
- `saveThenLoadRoundTrips`.
- `replaceWritesNewIdentity` (save A, save B, load B).
- `corruptCiphertextFailsAndKeepsBlob`.
- `clearFileRemovesBlob`.
- `clearFileReportsFailure` (make `client-certificate.bin` a non-empty directory).
- `clearKeyCallsProvider`.
- `missingKeyReportsKeyMissingAndKeepsBlob` (provider throws `UnrecoverableKeyException` on decrypt).
- `authFailureKeepsBlob`.

Use `sample()` from the RSA fixture in Task 1.

- [ ] **Step 2: Run the test and watch it fail**

```bash
./gradlew :org.fox.ttrss:testDebugUnitTest --tests "org.fox.ttrss.mtls.ClientCertificateStoreTest"
```

Expected: compilation failure because the store does not exist.

- [ ] **Step 3: Implement the store**

File name: `client-certificate.bin`. Use `getNoBackupFilesDir()` in `create(Context)`.

Container format:
- 4-byte magic `TTC1`
- 1-byte version `1`
- 12-byte IV
- AES/GCM ciphertext of `CertificatePayloadCodec.encode(certificate)`
- AAD is magic, version, and key alias `ttrss.client-certificate.v1`.

Production `CipherProvider`:
- Use `KeyStore.getInstance("AndroidKeyStore")`.
- Create an AES 256 key with `KeyGenParameterSpec.Builder(alias, PURPOSE_ENCRYPT | PURPOSE_DECRYPT)`, `BLOCK_MODE_GCM`, `ENCRYPTION_PADDING_NONE`, no user authentication.
- `getOrCreateKey()` creates a missing key.
- On `KeyPermanentlyInvalidatedException`, delete the key, create a new key, and retry the cipher once.
- `deleteKey()` deletes the alias.

Use `AtomicFile` from `androidx.core.util.AtomicFile` for writes. Start a write, write the container, `finishWrite`, and call `failWrite` on failure. On read, a missing file returns `null`.

Map:
- `AEADBadTagException` to `StoreException.Reason.AUTH`.
- `UnrecoverableKeyException` to `StoreException.Reason.KEY_MISSING`.
- Malformed container or codec failure to `StoreException.Reason.CORRUPT`.
- Other I/O or provider failures to `StoreException.Reason.IO`.

Do not delete the blob on any load failure. `clearFile()` deletes only the blob. `clearKey()` calls `CipherProvider.deleteKey()` and returns its success.

- [ ] **Step 4: Run the store test to verify it passes**

Run the command from Step 2. Expected: all store tests pass.

- [ ] **Step 5: Commit**

```bash
git add org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/ClientCertificateStore.java \
  org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/StoreException.java \
  org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/ClientCertificateStoreTest.java
git commit -m "feat: store client certificate encrypted"
```

---

### Task 3: Certificate Manager State Machine

**Files:**
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/ClientCertificateManager.java`
- Create: `org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/ClientCertificateManagerTest.java`

**Interfaces:**
- Consumes: `ClientCertificateStore`, `ClientCertificate`, `CertificateImportException`.
- Produces: `enum State { LOADING, NONE, READY, ERROR }`.
- Produces: `interface Listener { void onStateChanged(State state); }`.
- Produces: `interface ImportCallback { void onSuccess(); void onFailure(CertificateImportException.Reason reason); }`.
- Produces: `interface RemoveCallback { void onSuccess(boolean keyDeleted); void onFailure(StoreException.Reason reason); }`.
- Produces: `interface SslContextFactory { SSLContext create(ClientCertificate certificate) throws GeneralSecurityException; }`.
- Produces: `static ClientCertificateManager getInstance()`.
- Produces: `void initialize(Context context, SslContextFactory sslContextFactory)`.
- Produces: `void startLoad()`.
- Produces: `Snapshot ensureLoaded()`.
- Produces: `State getState()`, `Snapshot getSnapshot()`, `StoreException.Reason getLastError()`, `boolean hasBlob()`.
- Produces: `void importCertificate(byte[] pkcs12, char[] password, String displayName, ImportCallback callback)`.
- Produces: `void remove(RemoveCallback callback)`.
- Produces: `void addListener(Listener listener)`, `void removeListener(Listener listener)`.
- Produces: `static final class Snapshot { int getGeneration(); ClientCertificate getCertificate(); SSLContext getSslContext(); }`.

- [ ] **Step 1: Write the failing manager test**

Inject a fake store, a fake SSL-context factory, a direct executor, and a direct callback executor. Use `CountDownLatch` for the single-flight test.

Tests:
- `startsLoadingThenNoneWhenNoBlob`.
- `loadsReadySnapshot`.
- `loadFailureFailsClosed` (store throws `AUTH`; state `ERROR`; `ensureLoaded` keeps `ERROR`).
- `importSuccessSwapsSnapshotAndIncrementsGeneration`.
- `importFailureKeepsReadySnapshot` (parse throws `WRONG_PASSWORD`; old snapshot remains).
- `removeDeletesFileAndKeyThenNone`.
- `removeFileFailureKeepsPreviousState` (from `READY` and from `ERROR`).
- `removeKeyFailureSwapsNoneAndReportsKeyDeletedFalse`.
- `singleFlightLoadsOnce` (two threads, fake store counts calls).
- `loadOverlappingImportIsSerialized` (latch the load, start import, release, assert final `READY`).
- `listenerGetsCurrentStateImmediately`.
- `listenerNotifiedOnEveryTransition`.

- [ ] **Step 2: Run the test and watch it fail**

```bash
./gradlew :org.fox.ttrss:testDebugUnitTest --tests "org.fox.ttrss.mtls.ClientCertificateManagerTest"
```

Expected: compilation failure because the manager does not exist.

- [ ] **Step 3: Implement the manager**

Use a single `synchronized` lock for `ensureLoaded`, import, and remove. Keep `state`, `snapshot`, and `lastError` under that lock. Use `AtomicInteger` or an `int` generation under the lock. Notify listeners outside the lock through the injected callback executor.

`ensureLoaded()`:
- If the state is not `LOADING`, return the snapshot.
- Load from the store. `null` becomes `NONE`.
- Build the SSL context with the injected `SslContextFactory`. Task 4 supplies `MutualTls::createSslContext` from `Application.onCreate`.
- On success, `READY` with a snapshot. On failure, `ERROR` with the reason.
- Notify once.

`importCertificate`:
- Call `ensureLoaded` under the lock first.
- Parse, build the SSL context, save the store, then swap the snapshot.
- On any failure, keep the old state and callback with the typed reason.
- Zero the password in `finally`.
- The callback runs on the callback executor.

`remove`:
- Delete the file first. If it fails, keep the previous state and callback `IO`.
- Delete the key. Swap to `NONE` and increment the generation.
- Callback `onSuccess(keyDeleted)`.

Listeners:
- Use `CopyOnWriteArrayList<Listener>`.
- `addListener` adds the listener and posts the current state immediately.
- `removeListener` removes it.
- If the manager is not initialized, `getInstance()` still returns a manager in `LOADING`; test doubles use the package-private constructor.

- [ ] **Step 4: Run the manager test to verify it passes**

Run the command from Step 2. Expected: all manager tests pass.

- [ ] **Step 5: Commit**

```bash
git add org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/ClientCertificateManager.java \
  org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/ClientCertificateManagerTest.java
git commit -m "feat: add client certificate manager"
```

---

### Task 4: TLS Context, Redirects, and API Integration

**Files:**
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/MutualTls.java`
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/ApiClientSelector.java`
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/RedirectPolicy.java`
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/SameOriginRedirectInterceptor.java`
- Create: `org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/MutualTlsTest.java`
- Create: `org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/ApiClientSelectorTest.java`
- Create: `org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/RedirectPolicyTest.java`
- Create: `org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/SameOriginRedirectInterceptorTest.java`
- Modify: `org.fox.ttrss/src/main/java/org/fox/ttrss/ApiCommon.java`
- Modify: `org.fox.ttrss/src/main/java/org/fox/ttrss/Application.java`

**Interfaces:**
- Consumes: `ClientCertificateManager`, `ClientCertificateManager.Snapshot`, `ClientCertificate`.
- Produces: `static X509TrustManager MutualTls.trustManager()`.
- Produces: `static SSLContext MutualTls.createSslContext(ClientCertificate certificate)`.
- Produces: `static SSLSocketFactory MutualTls.socketFactory(SSLContext context)`.
- Produces: `static ApiClientSelector.Mode ApiClientSelector.select(State state, String ttrssUrl)` with `Mode { PLAIN, MTLS, ERROR }`.
- Produces: `static boolean RedirectPolicy.isRedirect(int code)`.
- Produces: `static boolean RedirectPolicy.keepsMethod(int code)`.
- Produces: `static String RedirectPolicy.methodFor(int code, String originalMethod)`.
- Produces: `static boolean RedirectPolicy.isSameOrigin(HttpUrl target, HttpUrl origin)`.
- Produces: `SameOriginRedirectInterceptor(Supplier<HttpUrl> originSupplier)` and header `X-TT-RSS-Redirect-Blocked`.
- Produces: `ClientCertificateManager.Snapshot` includes `SSLContext`.

- [ ] **Step 1: Write the failing selector and redirect tests**

`ApiClientSelectorTest` matrix:

```java
@Test public void noneUsesPlainForHttps() {
    assertEquals(Mode.PLAIN, ApiClientSelector.select(State.NONE, "https://example.com/tt-rss"));
}
@Test public void readyUsesMtlsForHttps() {
    assertEquals(Mode.MTLS, ApiClientSelector.select(State.READY, "https://example.com/tt-rss"));
}
@Test public void readyUsesPlainForHttp() {
    assertEquals(Mode.PLAIN, ApiClientSelector.select(State.READY, "http://example.com/tt-rss"));
}
@Test public void errorAlwaysFails() {
    assertEquals(Mode.ERROR, ApiClientSelector.select(State.ERROR, "https://example.com/tt-rss"));
}
@Test public void loadingFailsClosed() {
    assertEquals(Mode.ERROR, ApiClientSelector.select(State.LOADING, "https://example.com/tt-rss"));
}
```

`RedirectPolicyTest`:
- 301, 302, 303 map POST to GET.
- 307 and 308 keep the method.
- Relative `Location` resolves against `https://example.com/tt-rss/api/`.
- Same origin accepts scheme, host, and effective port.
- Different scheme, host, or port rejects.
- 304 is not a redirect.

`SameOriginRedirectInterceptorTest`:
- Same-origin 302 follows with GET.
- 307 replays the body.
- Cross-origin returns the 3xx with the blocked header.
- After five redirects, returns the 3xx with the blocked header.
- Origin supplier is read again for each redirect.

`MutualTlsTest`:
- Parse the RSA fixture, call `createSslContext`, assert non-null and `getSocketFactory()` non-null.
- Assert `trustManager()` is an `X509TrustManager`.
- Assert the trust manager comes from `TrustManagerFactory` with a null KeyStore by construction (review the code; do not add a permissive manager).

- [ ] **Step 2: Run the tests and watch them fail**

```bash
./gradlew :org.fox.ttrss:testDebugUnitTest --tests "org.fox.ttrss.mtls.ApiClientSelectorTest" \
  --tests "org.fox.ttrss.mtls.RedirectPolicyTest" \
  --tests "org.fox.ttrss.mtls.SameOriginRedirectInterceptorTest" \
  --tests "org.fox.ttrss.mtls.MutualTlsTest"
```

Expected: compilation failure because the classes do not exist.

- [ ] **Step 3: Implement the TLS and redirect classes**

`MutualTls`:
- Get the platform trust manager from `TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())` initialized with `(KeyStore) null`.
- Build an in-memory `PKCS12` KeyStore with `setKeyEntry("client", privateKey, randomPassword, chain)`. Initialize `KeyManagerFactory.getDefaultAlgorithm()` with it.
- Create `SSLContext.getInstance("TLS")` and initialize it with the key managers and the platform trust manager.
- Zero the random password in `finally`.
- Do not set a `HostnameVerifier`.

`ApiClientSelector`: as the matrix above. `LOADING` is defensive `ERROR`.

`RedirectPolicy`: 301/302/303/307/308 are redirects. 307/308 keep the method. 301/302/303 use GET. Same origin compares `scheme`, `host`, and `port` on `HttpUrl`.

`SameOriginRedirectInterceptor`:
- Read `originSupplier.get()` on each redirect.
- Follow at most five redirects.
- Resolve `Location` with `response.request().url().resolve(location)`.
- If the target is null, not a redirect, or not same-origin, add `X-TT-RSS-Redirect-Blocked: 1` and return the response.
- For 301/302/303, rebuild the request as GET with a null body and remove `Content-Type` and `Content-Length`.
- For 307/308, keep the method and body. If `body().isOneShot()`, block the redirect.
- Close each intermediate response.
- Preserve `Authorization` for same-origin requests.

- [ ] **Step 4: Integrate with `ApiCommon`**

- Add `CLIENT_CERTIFICATE_ERROR` and `REDIRECT_BLOCKED` to `ApiError` and `getErrorMessage`.
- Initialize the manager in `Application.onCreate` with `ClientCertificateManager.getInstance().initialize(this, MutualTls::createSslContext)` and `startLoad()`.
- Replace the static final `CLIENT` with a volatile cache of `{generation, mode, OkHttpClient}`.
- `getClient(context, mode, snapshot)`:
  - `PLAIN`: build the current client with the existing timeouts, `RetryInterceptor`, and progress interceptor.
  - `MTLS`: add `sslSocketFactory(MutualTls.socketFactory(snapshot.getSslContext()), MutualTls.trustManager())` and `addInterceptor(new SameOriginRedirectInterceptor(originSupplier))`; set `followRedirects(false)` and `followSslRedirects(false)`.
  - `originSupplier` reads `ttrss_url` from `SharedPreferences` on each call.
- `performRequest`:
  - Call `manager.ensureLoaded()`.
  - Select the mode. `ERROR` sets `CLIENT_CERTIFICATE_ERROR` and returns null.
  - Use the cached client for the mode and generation.
  - Check `X-TT-RSS-Redirect-Blocked` before the generic 3xx path and set `REDIRECT_BLOCKED`.
  - Catch `SSLHandshakeException` when the manager is `READY`: set `SSL_REJECTED` and append the certificate hint.
- `RetryInterceptor`: break before retrying when `e instanceof SSLException`.
- Keep username/password login and HTTP Basic auth unchanged.

- [ ] **Step 5: Run the TLS tests and the existing API-adjacent tests**

```bash
./gradlew :org.fox.ttrss:testDebugUnitTest --tests "org.fox.ttrss.mtls.*" \
  --tests "org.fox.ttrss.FeedsModelTest" --tests "org.fox.ttrss.HeadlinesPageLoaderTest"
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/MutualTls.java \
  org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/ApiClientSelector.java \
  org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/RedirectPolicy.java \
  org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/SameOriginRedirectInterceptor.java \
  org.fox.ttrss/src/main/java/org/fox/ttrss/ApiCommon.java \
  org.fox.ttrss/src/main/java/org/fox/ttrss/Application.java \
  org.fox.ttrss/src/test/java/org/fox/ttrss/mtls
git commit -m "feat: use client certificate for API requests"
```

---

### Task 5: Glide Image Routing and Cross-Origin Fallback

**Files:**
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/ImageOriginPolicy.java`
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/ImageClientFactory.java`
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/DynamicImageCallFactory.java`
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/CrossOriginImageCall.java`
- Create: `org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/ImageOriginPolicyTest.java`
- Create: `org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/CrossOriginImageCallTest.java`
- Create: `org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/ImageClientFactoryTest.java`
- Modify: `org.fox.ttrss/src/main/java/org/fox/ttrss/glide/OkHttpProgressGlideModule.java`

**Interfaces:**
- Consumes: `ClientCertificateManager`, `SameOriginRedirectInterceptor`, `MutualTls`.
- Produces: `static boolean ImageOriginPolicy.isTtrssOrigin(HttpUrl imageUrl, String ttrssUrl)`.
- Produces: `ImageClientFactory(Interceptor progressInterceptor)`.
- Produces: `OkHttpClient plainClient()`.
- Produces: `OkHttpClient mtlsClient(SSLContext context, X509TrustManager trust, Supplier<HttpUrl> originSupplier)`.
- Produces: `DynamicImageCallFactory(Context context, ImageClientFactory factory, ClientCertificateManager manager)` implements `Call.Factory`.
- Produces: `CrossOriginImageCall(Call delegate, Call.Factory plainFactory)` implements `Call`.

- [ ] **Step 1: Write the failing tests**

`ImageOriginPolicyTest`:
- Same HTTPS origin and default port match.
- Explicit port 443 matches.
- Different host, scheme, or port does not match.
- Path and query do not matter.
- Invalid `ttrss_url` does not match.
- `http` image URL does not match.

`CrossOriginImageCallTest`:
- A blocked 302 response is closed and the plain factory gets the resolved URL.
- Plain response is returned.
- `onFailure` forwards.
- `cancel()` cancels both calls.
- A non-blocked response returns unchanged.

`ImageClientFactoryTest`:
- `plainClient` and `mtlsClient` both include the supplied progress interceptor in `networkInterceptors()`.
- The mTLS client has `followRedirects() == false`.

- [ ] **Step 2: Run the tests and watch them fail**

```bash
./gradlew :org.fox.ttrss:testDebugUnitTest --tests "org.fox.ttrss.mtls.ImageOriginPolicyTest" \
  --tests "org.fox.ttrss.mtls.CrossOriginImageCallTest" \
  --tests "org.fox.ttrss.mtls.ImageClientFactoryTest"
```

Expected: compilation failure because the classes do not exist.

- [ ] **Step 3: Implement the image routing classes**

`ImageOriginPolicy`:
- Parse `ttrssUrl` with `HttpUrl.parse`.
- Require both URLs to be HTTPS.
- Compare `host()` and `port()`. `HttpUrl` returns the effective default port.
- Ignore path and query.

`ImageClientFactory`:
- `plainClient`: timeouts, no client certificate, normal redirects, progress network interceptor.
- `mtlsClient`: timeouts, client certificate, same-origin redirect interceptor, redirects disabled, progress network interceptor.
- Accept the existing progress interceptor from the Glide module.

`DynamicImageCallFactory`:
- On each `newCall`, read `ttrss_url` from `SharedPreferences`.
- If the image origin matches, call `manager.ensureLoaded()`:
  - `ERROR` returns a call that fails with `IOException("client certificate unavailable")`.
  - `READY` uses the current mTLS client and wraps it in `CrossOriginImageCall`.
  - `NONE` uses the plain client.
- Other image hosts use the plain client.
- Cache the mTLS client by snapshot generation.

`CrossOriginImageCall`:
- Delegate all `Call` methods, including OkHttp 5 tags and `addEventListener`.
- On `execute`, if the response has status 301/302/303/307/308 and `X-TT-RSS-Redirect-Blocked`, close it, resolve `Location`, build the redirected request, run it on the plain factory, and return that response.
- On `enqueue`, do the same through a callback wrapper.
- `cancel()` cancels the delegate and any active plain call.
- `clone()` creates a new wrapper around `delegate.clone()`.

- [ ] **Step 4: Wire Glide**

In `OkHttpProgressGlideModule.registerComponents`:
- Create the existing progress interceptor once with `DispatchingProgressListener`.
- Create `ImageClientFactory` and `DynamicImageCallFactory`.
- Register `new OkHttpUrlLoader.Factory(callFactory)`.
- Keep the existing `BitmapSizeDecoder` and `OptionsSizeResourceTranscoder` registrations.

- [ ] **Step 5: Run the image tests**

```bash
./gradlew :org.fox.ttrss:testDebugUnitTest --tests "org.fox.ttrss.mtls.Image*" \
  --tests "org.fox.ttrss.mtls.CrossOriginImageCallTest"
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/ImageOriginPolicy.java \
  org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/ImageClientFactory.java \
  org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/DynamicImageCallFactory.java \
  org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/CrossOriginImageCall.java \
  org.fox.ttrss/src/main/java/org/fox/ttrss/glide/OkHttpProgressGlideModule.java \
  org.fox.ttrss/src/test/java/org/fox/ttrss/mtls
git commit -m "feat: use client certificate for tt-rss images"
```

---

### Task 6: Network Settings UI and Final Verification

**Files:**
- Create: `org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/CertificateUiState.java`
- Create: `org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/CertificateUiStateTest.java`
- Modify: `org.fox.ttrss/src/main/java/org/fox/ttrss/NetworkPreferencesFragment.java`
- Modify: `org.fox.ttrss/src/main/res/xml/preferences_network.xml`
- Modify: `org.fox.ttrss/src/main/res/values/strings.xml`
- Modify: `org.fox.ttrss/src/main/res/xml/preferences.xml` only if the export note needs a summary change.

**Interfaces:**
- Consumes: `ClientCertificateManager` and its `State`, `Listener`, `ImportCallback`, `RemoveCallback`.
- Produces: `CertificateUiState.summaryRes(State state)` returns a string resource id, or `0` for `READY`.
- Produces: `CertificateUiState.canImport(State state)`.
- Produces: `CertificateUiState.showRemove(State state, boolean hasBlob)`.

- [ ] **Step 1: Write the failing UI-state test**

```java
package org.fox.ttrss.mtls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.fox.ttrss.R;
import org.junit.Test;

public class CertificateUiStateTest {
    @Test public void loadingDisablesActions() {
        assertFalse(CertificateUiState.canImport(ClientCertificateManager.State.LOADING));
        assertFalse(CertificateUiState.showRemove(ClientCertificateManager.State.LOADING, true));
        assertEquals(R.string.client_certificate_summary_loading,
                CertificateUiState.summaryRes(ClientCertificateManager.State.LOADING));
    }

    @Test public void noneShowsNotImportedAndAllowsImport() {
        assertTrue(CertificateUiState.canImport(ClientCertificateManager.State.NONE));
        assertFalse(CertificateUiState.showRemove(ClientCertificateManager.State.NONE, false));
        assertEquals(R.string.client_certificate_summary_none,
                CertificateUiState.summaryRes(ClientCertificateManager.State.NONE));
    }

    @Test public void errorShowsUnreadableAndAllowsRemove() {
        assertTrue(CertificateUiState.canImport(ClientCertificateManager.State.ERROR));
        assertTrue(CertificateUiState.showRemove(ClientCertificateManager.State.ERROR, true));
        assertEquals(R.string.client_certificate_summary_error,
                CertificateUiState.summaryRes(ClientCertificateManager.State.ERROR));
    }

    @Test public void readyHasNoFixedSummary() {
        assertTrue(CertificateUiState.canImport(ClientCertificateManager.State.READY));
        assertEquals(0, CertificateUiState.summaryRes(ClientCertificateManager.State.READY));
    }
}
```

- [ ] **Step 2: Run the test and watch it fail**

```bash
./gradlew :org.fox.ttrss:testDebugUnitTest --tests "org.fox.ttrss.mtls.CertificateUiStateTest"
```

Expected: compilation failure because `CertificateUiState` does not exist.

- [ ] **Step 3: Implement `CertificateUiState` and the UI**

`preferences_network.xml`:
- Add a `PreferenceCategory` titled `Client certificate`.
- Add `client_certificate_import` and `client_certificate_remove` with `android:persistent="false"`.
- Add a static note preference for the WebView/export limitation.

`NetworkPreferencesFragment`:
- Register `ActivityResultContracts.OpenDocument` with `application/x-pkcs12`, `application/pkcs12`, `application/octet-stream`, and `*/*`.
- Register a manager listener in `onStart`, remove it in `onStop`. The manager delivers the current state immediately.
- Read the selected URI on an executor with a 5 MB cap. If `ttrss_url` is not HTTPS, show `client_certificate_http_warning`.
- Show the optional password dialog. Copy the `Editable` into a `char[]`, clear the field, and pass the array to the manager. Zero the array in `finally`.
- Confirmed imports run in the manager, not the fragment.
- On failure, map `CertificateImportException.Reason` to the matching string. Keep the old certificate.
- On success, toast `client_certificate_imported`.
- Remove asks for confirmation, calls `manager.remove`, and maps the result to the success or cleanup-warning string.
- `renderState` uses `CertificateUiState`. For `READY`, use `certificate.getSubject()` and `DateFormat.getDateInstance().format(new Date(notAfterEpochMillis))`.
- Guard all callbacks with `isAdded()`.

Strings to add:
`client_certificate_category`, `client_certificate_title`,
`client_certificate_summary_loading`, `client_certificate_summary_none`,
`client_certificate_summary_ready`, `client_certificate_summary_error`,
`client_certificate_import`, `client_certificate_replace`,
`client_certificate_remove`, `client_certificate_remove_confirm`,
`client_certificate_replace_confirm`, `client_certificate_password_title`,
`client_certificate_password_hint`, `client_certificate_imported`,
`client_certificate_removed`, `client_certificate_error_unreadable`,
`client_certificate_error_wrong_password`, `client_certificate_error_missing_key`,
`client_certificate_error_missing_chain`,
`client_certificate_error_unsupported_key`,
`client_certificate_error_expired`, `client_certificate_error_too_large`,
`client_certificate_remove_failed`, `client_certificate_remove_cleanup_failed`,
`client_certificate_http_warning`, `client_certificate_note`,
`error_client_certificate`, `error_redirect_blocked`,
`error_ssl_certificate_hint`.

- [ ] **Step 4: Run the UI-state test and compile the app**

```bash
./gradlew :org.fox.ttrss:testDebugUnitTest --tests "org.fox.ttrss.mtls.CertificateUiStateTest"
./gradlew :org.fox.ttrss:assembleDebug
```

Expected: the test passes and the debug APK builds.

- [ ] **Step 5: Run the full gate**

```bash
./gradlew --no-daemon check assembleDebug
```

Expected: `BUILD SUCCESSFUL`. Lint must report no errors. The debug APK is at `org.fox.ttrss/build/outputs/apk/debug/org.fox.ttrss-debug.apk`.

- [ ] **Step 6: Manual verification**

Perform these checks on a device or emulator when available:
- Import the RSA fixture with password `testpass`.
- Import the EC fixture.
- Enter a wrong password and confirm the old certificate stays.
- Replace the certificate and confirm the summary changes.
- Remove the certificate and confirm the summary returns to "Not imported".
- Configure an HTTP URL and confirm the warning.
- Confirm a user-installed CA still validates.
- Confirm a cross-origin image redirect loads without the certificate.
- Confirm article WebView content still loads.

Record the result in the task ledger. If no device is available, record "manual device checks not run" and say so in the final message.

- [ ] **Step 7: Commit**

```bash
git add org.fox.ttrss/src/main/java/org/fox/ttrss/mtls/CertificateUiState.java \
  org.fox.ttrss/src/main/java/org/fox/ttrss/NetworkPreferencesFragment.java \
  org.fox.ttrss/src/main/res/xml/preferences_network.xml \
  org.fox.ttrss/src/main/res/xml/preferences.xml \
  org.fox.ttrss/src/main/res/values/strings.xml \
  org.fox.ttrss/src/test/java/org/fox/ttrss/mtls/CertificateUiStateTest.java
git commit -m "feat: add client certificate settings"
```

---

## Pre-flight Interface Check

- Task 2 uses `ClientCertificate` and `CertificatePayloadCodec` from Task 1.
- Task 3 uses `ClientCertificateStore` and `CertificateImportException` from Tasks 1-2.
- Task 4 uses `ClientCertificateManager.Snapshot` from Task 3 and adds `MutualTls`.
- Task 5 uses `ClientCertificateManager` and `SameOriginRedirectInterceptor` from Tasks 3-4.
- Task 6 uses manager states and `CertificateUiState` from Tasks 3 and 6.

No shared-interface conflict is expected. If a name or signature differs during execution, record a `Ruling:` in the ledger and update the consuming task.
