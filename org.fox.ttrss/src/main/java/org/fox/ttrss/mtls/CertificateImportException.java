package org.fox.ttrss.mtls;

public final class CertificateImportException extends Exception {
	public enum Reason {
		UNREADABLE,
		WRONG_PASSWORD,
		MISSING_KEY,
		MISSING_CHAIN,
		UNSUPPORTED_KEY,
		EXPIRED,
		NOT_YET_VALID,
		STORE_ERROR
	}

	private final Reason m_reason;

	public CertificateImportException(Reason reason, String message) {
		super(message);
		m_reason = reason;
	}

	public CertificateImportException(Reason reason, String message, Throwable cause) {
		super(message, cause);
		m_reason = reason;
	}

	public Reason getReason() {
		return m_reason;
	}
}
