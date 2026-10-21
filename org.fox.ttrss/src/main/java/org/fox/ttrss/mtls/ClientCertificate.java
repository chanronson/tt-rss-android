package org.fox.ttrss.mtls;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class ClientCertificate {
	private final String m_displayName;
	private final String m_subject;
	private final long m_notAfterEpochMillis;
	private final String m_keyAlgorithm;
	private final PrivateKey m_privateKey;
	private final List<X509Certificate> m_chain;

	public ClientCertificate(String displayName, String subject, long notAfterEpochMillis,
			String keyAlgorithm, PrivateKey privateKey, List<X509Certificate> chain) {
		m_displayName = displayName;
		m_subject = subject;
		m_notAfterEpochMillis = notAfterEpochMillis;
		m_keyAlgorithm = keyAlgorithm;
		m_privateKey = Objects.requireNonNull(privateKey);
		m_chain = Collections.unmodifiableList(new ArrayList<>(Objects.requireNonNull(chain)));
	}

	public String getDisplayName() {
		return m_displayName;
	}

	public String getSubject() {
		return m_subject;
	}

	public long getNotAfterEpochMillis() {
		return m_notAfterEpochMillis;
	}

	public String getKeyAlgorithm() {
		return m_keyAlgorithm;
	}

	public PrivateKey getPrivateKey() {
		return m_privateKey;
	}

	public List<X509Certificate> getChain() {
		return m_chain;
	}
}
