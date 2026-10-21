package org.fox.ttrss.mtls;

import static org.junit.Assert.assertNotNull;

import org.junit.Test;

import java.io.InputStream;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

public class MutualTlsTest {
	private ClientCertificate sample() throws Exception {
		try (InputStream in = getClass().getResourceAsStream("/mtls/client-rsa.p12")) {
			assertNotNull(in);
			return ClientCertificateParser.parse(in.readAllBytes(), "testpass".toCharArray(),
					"client-rsa.p12", System.currentTimeMillis());
		}
	}

	@Test
	public void createsSslContextAndSocketFactory() throws Exception {
		SSLContext context = MutualTls.createSslContext(sample());

		assertNotNull(context);
		assertNotNull(context.getSocketFactory());
	}

	@Test
	public void usesX509TrustManager() throws Exception {
		X509TrustManager trustManager = MutualTls.trustManager();

		assertNotNull(trustManager);
	}
}
