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
