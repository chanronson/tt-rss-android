package org.fox.ttrss.mtls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.UnrecoverableKeyException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ClientCertificateStoreTest {

	@Rule
	public TemporaryFolder m_folder = new TemporaryFolder();

	private static class FakeCipherProvider implements ClientCertificateStore.CipherProvider {
		private final SecretKey m_key = new SecretKeySpec(new byte[32], "AES");
		boolean deleted;
		boolean throwMissingKey;

		@Override
		public Cipher encryptCipher(byte[] iv, byte[] aad) throws GeneralSecurityException {
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, m_key, new GCMParameterSpec(128, iv));
			cipher.updateAAD(aad);
			return cipher;
		}

		@Override
		public Cipher decryptCipher(byte[] iv, byte[] aad) throws GeneralSecurityException {
			if (throwMissingKey) throw new UnrecoverableKeyException("missing key");

			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, m_key, new GCMParameterSpec(128, iv));
			cipher.updateAAD(aad);
			return cipher;
		}

		@Override
		public boolean deleteKey() {
			deleted = true;
			return true;
		}
	}

	private ClientCertificate sample(String name, String password) throws Exception {
		try (InputStream in = getClass().getResourceAsStream("/mtls/" + name)) {
			assertNotNull(in);
			return ClientCertificateParser.parse(in.readAllBytes(), password.toCharArray(),
					name, System.currentTimeMillis());
		}
	}

	private ClientCertificateStore store(FakeCipherProvider provider) throws Exception {
		return new ClientCertificateStore(m_folder.getRoot(), provider);
	}

	private File blob() {
		return new File(m_folder.getRoot(), "client-certificate.bin");
	}

	@Test
	public void saveThenLoadRoundTrips() throws Exception {
		FakeCipherProvider provider = new FakeCipherProvider();
		ClientCertificateStore store = store(provider);
		ClientCertificate source = sample("client-rsa.p12", "testpass");

		store.save(source);
		ClientCertificate loaded = store.load();

		assertNotNull(loaded);
		assertEquals(source.getDisplayName(), loaded.getDisplayName());
		assertEquals(source.getKeyAlgorithm(), loaded.getKeyAlgorithm());
		assertEquals(source.getChain().size(), loaded.getChain().size());
	}

	@Test
	public void missingBlobLoadsNull() throws Exception {
		FakeCipherProvider provider = new FakeCipherProvider();
		assertNull(store(provider).load());
		assertFalse(store(provider).hasBlob());
	}

	@Test
	public void replaceWritesNewIdentity() throws Exception {
		FakeCipherProvider provider = new FakeCipherProvider();
		ClientCertificateStore store = store(provider);
		store.save(sample("client-rsa.p12", "testpass"));
		store.save(sample("client-ec.p12", "testpass"));

		assertEquals("EC", store.load().getKeyAlgorithm());
	}

	@Test
	public void corruptCiphertextFailsAndKeepsBlob() throws Exception {
		FakeCipherProvider provider = new FakeCipherProvider();
		ClientCertificateStore store = store(provider);
		store.save(sample("client-rsa.p12", "testpass"));

		byte[] bytes = java.nio.file.Files.readAllBytes(blob().toPath());
		bytes[bytes.length - 1] ^= 1;
		try (FileOutputStream out = new FileOutputStream(blob())) {
			out.write(bytes);
		}

		try {
			store.load();
			fail("expected failure");
		} catch (StoreException e) {
			assertEquals(StoreException.Reason.AUTH, e.getReason());
		}

		assertTrue(store.hasBlob());
	}

	@Test
	public void missingKeyReportsKeyMissingAndKeepsBlob() throws Exception {
		FakeCipherProvider provider = new FakeCipherProvider();
		ClientCertificateStore store = store(provider);
		store.save(sample("client-rsa.p12", "testpass"));
		provider.throwMissingKey = true;

		try {
			store.load();
			fail("expected failure");
		} catch (StoreException e) {
			assertEquals(StoreException.Reason.KEY_MISSING, e.getReason());
		}

		assertTrue(store.hasBlob());
	}

	@Test
	public void clearFileRemovesBlob() throws Exception {
		FakeCipherProvider provider = new FakeCipherProvider();
		ClientCertificateStore store = store(provider);
		store.save(sample("client-rsa.p12", "testpass"));

		assertTrue(store.clearFile());
		assertFalse(store.hasBlob());
	}

	@Test
	public void clearFileReportsFailure() throws Exception {
		FakeCipherProvider provider = new FakeCipherProvider();
		ClientCertificateStore store = store(provider);
		store.save(sample("client-rsa.p12", "testpass"));

		assertTrue(blob().delete());
		assertTrue(blob().mkdir());
		assertTrue(new File(blob(), "child").createNewFile());

		assertFalse(store.clearFile());
		assertTrue(store.hasBlob());
	}

	@Test
	public void clearKeyCallsProvider() throws Exception {
		FakeCipherProvider provider = new FakeCipherProvider();
		ClientCertificateStore store = store(provider);
		store.save(sample("client-rsa.p12", "testpass"));

		assertTrue(store.clearKey());
		assertTrue(provider.deleted);
	}
}
