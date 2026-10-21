package org.fox.ttrss.mtls;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Arrays;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public final class MutualTls {
	private static final String KEY_ALIAS = "client";
	private static volatile X509TrustManager sTrustManager;

	private MutualTls() {
	}

	public static X509TrustManager trustManager() throws GeneralSecurityException {
		X509TrustManager trustManager = sTrustManager;

		if (trustManager != null) return trustManager;

		synchronized (MutualTls.class) {
			if (sTrustManager == null) {
				TrustManagerFactory factory = TrustManagerFactory.getInstance(
						TrustManagerFactory.getDefaultAlgorithm());
				factory.init((KeyStore) null);

				for (TrustManager candidate : factory.getTrustManagers()) {
					if (candidate instanceof X509TrustManager) {
						sTrustManager = (X509TrustManager) candidate;
						break;
					}
				}

				if (sTrustManager == null) {
					throw new GeneralSecurityException("no X509 trust manager");
				}
			}

			return sTrustManager;
		}
	}

	public static SSLContext createSslContext(ClientCertificate certificate)
			throws GeneralSecurityException {
		char[] password = new char[32];
		SecureRandom random = new SecureRandom();
		for (int i = 0; i < password.length; i++) {
			password[i] = (char) ('a' + random.nextInt(26));
		}

		try {
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			try {
				keyStore.load(null, null);
			} catch (java.io.IOException e) {
				throw new GeneralSecurityException("cannot create in-memory keystore", e);
			}
			Certificate[] chain = certificate.getChain().toArray(new Certificate[0]);
			keyStore.setKeyEntry(KEY_ALIAS, certificate.getPrivateKey(), password, chain);

			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
					KeyManagerFactory.getDefaultAlgorithm());
			keyManagerFactory.init(keyStore, password);

			SSLContext context = SSLContext.getInstance("TLS");
			context.init(keyManagerFactory.getKeyManagers(),
					new TrustManager[]{trustManager()}, new SecureRandom());

			return context;
		} finally {
			Arrays.fill(password, '\0');
		}
	}

	public static SSLSocketFactory socketFactory(SSLContext context) {
		return context.getSocketFactory();
	}
}
