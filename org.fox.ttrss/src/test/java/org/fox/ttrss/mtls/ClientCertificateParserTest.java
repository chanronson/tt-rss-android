package org.fox.ttrss.mtls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
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
