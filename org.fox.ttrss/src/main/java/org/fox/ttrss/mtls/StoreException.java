package org.fox.ttrss.mtls;

public final class StoreException extends Exception {
	public enum Reason {
		IO,
		AUTH,
		KEY_MISSING,
		CORRUPT
	}

	private final Reason m_reason;

	public StoreException(Reason reason, String message) {
		super(message);
		m_reason = reason;
	}

	public StoreException(Reason reason, String message, Throwable cause) {
		super(message, cause);
		m_reason = reason;
	}

	public Reason getReason() {
		return m_reason;
	}
}
