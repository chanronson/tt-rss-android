package org.fox.ttrss.mtls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Locale;

public final class ClientCertificateParser {
	private ClientCertificateParser() {
	}

	public static ClientCertificate parse(byte[] pkcs12, char[] password, String displayName,
			long nowEpochMillis) throws CertificateImportException {
		if (pkcs12 == null || pkcs12.length == 0) {
			throw new CertificateImportException(CertificateImportException.Reason.UNREADABLE,
					"empty certificate bundle");
		}

		char[] passCopy = password == null ? new char[0] : Arrays.copyOf(password, password.length);

		try {
			KeyStore store = KeyStore.getInstance("PKCS12");
			try {
				store.load(new ByteArrayInputStream(pkcs12), passCopy);
			} catch (IOException e) {
				throw mapLoadFailure(e);
			} catch (GeneralSecurityException e) {
				throw new CertificateImportException(
						CertificateImportException.Reason.UNREADABLE,
						"cannot load PKCS#12 bundle", e);
			}

			Enumeration<String> aliases = store.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();

				if (!store.isKeyEntry(alias)) continue;

				Key key;
				try {
					key = store.getKey(alias, passCopy);
				} catch (UnrecoverableKeyException e) {
					throw new CertificateImportException(
							CertificateImportException.Reason.WRONG_PASSWORD,
							"cannot decrypt private key", e);
				} catch (GeneralSecurityException e) {
					throw new CertificateImportException(
							CertificateImportException.Reason.UNREADABLE,
							"cannot read private key", e);
				}

				if (!(key instanceof PrivateKey)) continue;

				Certificate[] chain = store.getCertificateChain(alias);

				if (chain == null || chain.length == 0) {
					throw new CertificateImportException(
							CertificateImportException.Reason.MISSING_CHAIN,
							"certificate chain is empty");
				}

				if (!(chain[0] instanceof X509Certificate)) {
					throw new CertificateImportException(
							CertificateImportException.Reason.MISSING_CHAIN,
							"certificate chain is not X.509");
				}

				X509Certificate leaf = (X509Certificate) chain[0];
				String algorithm = key.getAlgorithm();

				if (!"RSA".equalsIgnoreCase(algorithm) && !"EC".equalsIgnoreCase(algorithm)) {
					throw new CertificateImportException(
							CertificateImportException.Reason.UNSUPPORTED_KEY,
							"unsupported key algorithm: " + algorithm);
				}

				long notBefore = leaf.getNotBefore().getTime();
				long notAfter = leaf.getNotAfter().getTime();

				if (nowEpochMillis < notBefore) {
					throw new CertificateImportException(
							CertificateImportException.Reason.NOT_YET_VALID,
							"certificate is not valid yet");
				}

				if (nowEpochMillis > notAfter) {
					throw new CertificateImportException(
							CertificateImportException.Reason.EXPIRED,
							"certificate is expired");
				}

				java.util.List<X509Certificate> certificates = new java.util.ArrayList<>();
				for (Certificate item : chain) {
					if (!(item instanceof X509Certificate)) {
						throw new CertificateImportException(
								CertificateImportException.Reason.MISSING_CHAIN,
								"certificate chain is not X.509");
					}
					certificates.add((X509Certificate) item);
				}

				String subject = leaf.getSubjectX500Principal().getName();
				String name = displayName == null || displayName.isEmpty() ? subject : displayName;

				return new ClientCertificate(name, subject, notAfter, algorithm,
						(PrivateKey) key, certificates);
			}

			throw new CertificateImportException(CertificateImportException.Reason.MISSING_KEY,
					"bundle has no private key");
		} catch (CertificateImportException e) {
			throw e;
		} catch (GeneralSecurityException e) {
			throw new CertificateImportException(CertificateImportException.Reason.UNREADABLE,
					"cannot inspect PKCS#12 bundle", e);
		} finally {
			Arrays.fill(passCopy, '\0');
		}
	}

	private static CertificateImportException mapLoadFailure(IOException e) {
		String message = e.getMessage() == null ? "" : e.getMessage().toLowerCase(Locale.ROOT);

		if (message.contains("password") || message.contains("decrypt")
				|| e.getCause() instanceof UnrecoverableKeyException) {
			return new CertificateImportException(
					CertificateImportException.Reason.WRONG_PASSWORD,
					"cannot decrypt PKCS#12 bundle", e);
		}

		return new CertificateImportException(CertificateImportException.Reason.UNREADABLE,
				"cannot load PKCS#12 bundle", e);
	}
}
