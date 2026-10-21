package org.fox.ttrss.mtls;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;

import androidx.core.util.AtomicFile;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class ClientCertificateStore {
	public interface CipherProvider {
		Cipher encryptCipher(byte[] iv, byte[] aad) throws GeneralSecurityException;

		Cipher decryptCipher(byte[] iv, byte[] aad) throws GeneralSecurityException;

		boolean deleteKey();
	}

	private static final String FILE_NAME = "client-certificate.bin";
	private static final byte[] MAGIC = {'T', 'T', 'C', '1'};
	private static final byte VERSION = 1;
	private static final int IV_LENGTH = 12;
	private static final int TAG_BITS = 128;
	private static final String TRANSFORMATION = "AES/GCM/NoPadding";
	private static final String KEY_ALIAS = "ttrss.client-certificate.v1";

	private final File m_file;
	private final CipherProvider m_cipherProvider;

	public ClientCertificateStore(File directory, CipherProvider cipherProvider) {
		m_file = new File(directory, FILE_NAME);
		m_cipherProvider = cipherProvider;
	}

	public static ClientCertificateStore create(Context context) {
		return new ClientCertificateStore(context.getNoBackupFilesDir(),
				new AndroidKeystoreCipherProvider());
	}

	public boolean hasBlob() {
		return m_file.exists();
	}

	public ClientCertificate load() throws StoreException {
		byte[] container;

		if (m_file.isDirectory()) {
			throw new StoreException(StoreException.Reason.CORRUPT,
					"certificate store path is a directory");
		}

		try {
			container = new AtomicFile(m_file).readFully();
		} catch (FileNotFoundException e) {
			return null;
		} catch (IOException e) {
			throw new StoreException(StoreException.Reason.IO, "cannot read certificate store", e);
		}

		if (container.length < MAGIC.length + 1 + IV_LENGTH) {
			throw new StoreException(StoreException.Reason.CORRUPT, "certificate store is truncated");
		}

		for (int i = 0; i < MAGIC.length; i++) {
			if (container[i] != MAGIC[i]) {
				throw new StoreException(StoreException.Reason.CORRUPT,
						"certificate store has bad magic");
			}
		}

		if (container[MAGIC.length] != VERSION) {
			throw new StoreException(StoreException.Reason.CORRUPT,
					"certificate store has unsupported version");
		}

		int offset = MAGIC.length + 1;
		byte[] iv = Arrays.copyOfRange(container, offset, offset + IV_LENGTH);
		byte[] ciphertext = Arrays.copyOfRange(container, offset + IV_LENGTH, container.length);

		byte[] payload = null;

		try {
			Cipher cipher = m_cipherProvider.decryptCipher(iv, aad());
			payload = cipher.doFinal(ciphertext);
			return CertificatePayloadCodec.decode(payload);
		} catch (AEADBadTagException e) {
			throw new StoreException(StoreException.Reason.AUTH,
					"certificate store authentication failed", e);
		} catch (UnrecoverableKeyException e) {
			throw new StoreException(StoreException.Reason.KEY_MISSING,
					"certificate store key is missing", e);
		} catch (CertificateImportException e) {
			throw new StoreException(StoreException.Reason.CORRUPT,
					"certificate payload is corrupt", e);
		} catch (GeneralSecurityException e) {
			throw new StoreException(StoreException.Reason.IO,
					"cannot decrypt certificate store", e);
		} finally {
			if (payload != null) Arrays.fill(payload, (byte) 0);
			Arrays.fill(ciphertext, (byte) 0);
		}
	}

	public void save(ClientCertificate certificate) throws StoreException {
		byte[] payload = CertificatePayloadCodec.encode(certificate);
		byte[] iv = new byte[IV_LENGTH];
		byte[] ciphertext = null;
		new SecureRandom().nextBytes(iv);

		try {
			Cipher cipher = m_cipherProvider.encryptCipher(iv, aad());
			ciphertext = cipher.doFinal(payload);

			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			buffer.write(MAGIC, 0, MAGIC.length);
			buffer.write(VERSION);
			buffer.write(iv, 0, iv.length);
			buffer.write(ciphertext, 0, ciphertext.length);

			byte[] container = buffer.toByteArray();
			AtomicFile atomicFile = new AtomicFile(m_file);
			FileOutputStream out = null;

			try {
				out = atomicFile.startWrite();
				out.write(container);
				atomicFile.finishWrite(out);
			} catch (IOException e) {
				if (out != null) atomicFile.failWrite(out);
				throw new StoreException(StoreException.Reason.IO,
						"cannot write certificate store", e);
			}
		} catch (GeneralSecurityException e) {
			throw new StoreException(StoreException.Reason.IO,
					"cannot encrypt certificate store", e);
		} finally {
			Arrays.fill(payload, (byte) 0);
			if (ciphertext != null) Arrays.fill(ciphertext, (byte) 0);
		}
	}

	public boolean clearFile() {
		if (!m_file.exists()) return true;

		try {
			new AtomicFile(m_file).delete();
			return !m_file.exists();
		} catch (RuntimeException e) {
			return false;
		}
	}

	public boolean clearKey() {
		return m_cipherProvider.deleteKey();
	}

	private static byte[] aad() {
		byte[] alias = KEY_ALIAS.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
		byte[] aad = new byte[MAGIC.length + 1 + alias.length];

		System.arraycopy(MAGIC, 0, aad, 0, MAGIC.length);
		aad[MAGIC.length] = VERSION;
		System.arraycopy(alias, 0, aad, MAGIC.length + 1, alias.length);

		return aad;
	}

	private static class AndroidKeystoreCipherProvider implements CipherProvider {
		private static final String ANDROID_KEYSTORE = "AndroidKeyStore";

		@Override
		public Cipher encryptCipher(byte[] iv, byte[] aad) throws GeneralSecurityException {
			return createCipher(Cipher.ENCRYPT_MODE, iv, aad);
		}

		@Override
		public Cipher decryptCipher(byte[] iv, byte[] aad) throws GeneralSecurityException {
			return createCipher(Cipher.DECRYPT_MODE, iv, aad);
		}

		@Override
		public boolean deleteKey() {
			try {
				KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
				keyStore.load(null);
				keyStore.deleteEntry(KEY_ALIAS);
				return true;
			} catch (Exception e) {
				return false;
			}
		}

		private Cipher createCipher(int mode, byte[] iv, byte[] aad)
				throws GeneralSecurityException {
			try {
				return initCipher(mode, iv, aad, getOrCreateKey());
			} catch (KeyPermanentlyInvalidatedException | InvalidAlgorithmParameterException e) {
				deleteKey();
				return initCipher(mode, iv, aad, getOrCreateKey());
			}
		}

		private Cipher initCipher(int mode, byte[] iv, byte[] aad, SecretKey key)
				throws GeneralSecurityException {
			Cipher cipher = Cipher.getInstance(TRANSFORMATION);
			cipher.init(mode, key, new GCMParameterSpec(TAG_BITS, iv));
			cipher.updateAAD(aad);
			return cipher;
		}

		private SecretKey getOrCreateKey() throws GeneralSecurityException {
			KeyStore keyStore;

			try {
				keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
				keyStore.load(null);
			} catch (IOException e) {
				throw new GeneralSecurityException("cannot open Android Keystore", e);
			}

			if (keyStore.containsAlias(KEY_ALIAS)) {
				try {
					Key key = keyStore.getKey(KEY_ALIAS, null);
					if (key instanceof SecretKey) return (SecretKey) key;
				} catch (UnrecoverableKeyException e) {
					keyStore.deleteEntry(KEY_ALIAS);
				}
			}

			KeyGenerator generator = KeyGenerator.getInstance(
					KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
			generator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
					KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
					.setBlockModes(KeyProperties.BLOCK_MODE_GCM)
					.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
					.setRandomizedEncryptionRequired(false)
					.setKeySize(256)
					.build());

			return generator.generateKey();
		}
	}
}
