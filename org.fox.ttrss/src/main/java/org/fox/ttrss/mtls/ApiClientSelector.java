package org.fox.ttrss.mtls;

import okhttp3.HttpUrl;

public final class ApiClientSelector {
	public enum Mode {
		PLAIN,
		MTLS,
		ERROR
	}

	private ApiClientSelector() {
	}

	public static Mode select(ClientCertificateManager.State state, String ttrssUrl) {
		if (state == ClientCertificateManager.State.ERROR
				|| state == ClientCertificateManager.State.LOADING) {
			return Mode.ERROR;
		}

		if (state == ClientCertificateManager.State.NONE) return Mode.PLAIN;

		if (state == ClientCertificateManager.State.READY) {
			HttpUrl url = HttpUrl.parse(ttrssUrl == null ? "" : ttrssUrl.trim());
			return url != null && url.isHttps() ? Mode.MTLS : Mode.PLAIN;
		}

		return Mode.ERROR;
	}
}
