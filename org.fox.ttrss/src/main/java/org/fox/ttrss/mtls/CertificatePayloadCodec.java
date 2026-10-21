package org.fox.ttrss.mtls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public final class CertificatePayloadCodec {
	private static final int VERSION = 1;
	private static final int MAX_TOTAL_BYTES = 5 * 1024 * 1024;
	private static final int MAX_TEXT_BYTES = 4096;
	private static final int MAX_ALGORITHM_BYTES = 64;
	private static final int MAX_KEY_BYTES = 65536;
	private static final int MAX_CERTIFICATE_BYTES = 65536;
	private static final int MAX_CHAIN_LENGTH = 10;

	private CertificatePayloadCodec() {
	}

	public static byte[] encode(ClientCertificate certificate) {
		try {
			ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			DataOutputStream out = new DataOutputStream(buffer);

			out.writeInt(VERSION);
			writeString(out, certificate.getDisplayName(), MAX_TEXT_BYTES);
			writeString(out, certificate.getSubject(), MAX_TEXT_BYTES);
			out.writeLong(certificate.getNotAfterEpochMillis());
			writeString(out, certificate.getKeyAlgorithm(), MAX_ALGORITHM_BYTES);

			byte[] keyBytes = certificate.getPrivateKey().getEncoded();
			if (keyBytes == null) {
				throw new IllegalArgumentException("private key has no PKCS#8 encoding");
			}
			writeBytes(out, keyBytes, MAX_KEY_BYTES);

			List<X509Certificate> chain = certificate.getChain();
			if (chain.isEmpty() || chain.size() > MAX_CHAIN_LENGTH) {
				throw new IllegalArgumentException("invalid certificate chain length");
			}

			out.writeInt(chain.size());
			for (X509Certificate item : chain) {
				writeBytes(out, item.getEncoded(), MAX_CERTIFICATE_BYTES);
			}

			out.flush();

			byte[] payload = buffer.toByteArray();
			if (payload.length > MAX_TOTAL_BYTES) {
				throw new IllegalArgumentException("certificate payload is too large");
			}

			return payload;
		} catch (IOException | java.security.cert.CertificateEncodingException e) {
			throw new IllegalArgumentException("cannot encode certificate", e);
		}
	}

	public static ClientCertificate decode(byte[] payload) throws CertificateImportException {
		if (payload == null || payload.length > MAX_TOTAL_BYTES) {
			throw unreadable("invalid certificate payload size", null);
		}

		try (DataInputStream in = new DataInputStream(new ByteArrayInputStream(payload))) {
			int version = in.readInt();
			if (version != VERSION) {
				throw unreadable("unsupported certificate payload version", null);
			}

			String displayName = readString(in, MAX_TEXT_BYTES);
			String subject = readString(in, MAX_TEXT_BYTES);
			long notAfter = in.readLong();
			String algorithm = readString(in, MAX_ALGORITHM_BYTES);
			byte[] keyBytes = readBytes(in, MAX_KEY_BYTES, "private key");

			int chainLength = in.readInt();
			if (chainLength < 1 || chainLength > MAX_CHAIN_LENGTH) {
				throw unreadable("invalid certificate chain length", null);
			}

			KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
			PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));

			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			List<X509Certificate> chain = new ArrayList<>(chainLength);

			for (int i = 0; i < chainLength; i++) {
				byte[] der = readBytes(in, MAX_CERTIFICATE_BYTES, "certificate");
				java.security.cert.Certificate certificate = certificateFactory.generateCertificate(
						new ByteArrayInputStream(der));

				if (!(certificate instanceof X509Certificate)) {
					throw unreadable("certificate is not X.509", null);
				}

				chain.add((X509Certificate) certificate);
			}

			if (in.read() != -1) {
				throw unreadable("trailing certificate payload data", null);
			}

			return new ClientCertificate(displayName, subject, notAfter, algorithm,
					privateKey, chain);
		} catch (CertificateImportException e) {
			throw e;
		} catch (Exception e) {
			throw unreadable("cannot decode certificate payload", e);
		}
	}

	private static void writeString(DataOutputStream out, String value, int maxBytes)
			throws IOException {
		byte[] bytes = value == null ? new byte[0] : value.getBytes(StandardCharsets.UTF_8);
		writeBytes(out, bytes, maxBytes);
	}

	private static void writeBytes(DataOutputStream out, byte[] bytes, int maxBytes)
			throws IOException {
		if (bytes.length > maxBytes) {
			throw new IllegalArgumentException("certificate field is too large");
		}

		out.writeInt(bytes.length);
		out.write(bytes);
	}

	private static String readString(DataInputStream in, int maxBytes) throws IOException,
			CertificateImportException {
		return new String(readBytes(in, maxBytes, "text"), StandardCharsets.UTF_8);
	}

	private static byte[] readBytes(DataInputStream in, int maxBytes, String label)
			throws IOException, CertificateImportException {
		int length = in.readInt();

		if (length < 0 || length > maxBytes) {
			throw unreadable("invalid " + label + " length", null);
		}

		byte[] bytes = new byte[length];
		in.readFully(bytes);
		return bytes;
	}

	private static CertificateImportException unreadable(String message, Throwable cause) {
		return new CertificateImportException(
				CertificateImportException.Reason.UNREADABLE, message, cause);
	}
}
