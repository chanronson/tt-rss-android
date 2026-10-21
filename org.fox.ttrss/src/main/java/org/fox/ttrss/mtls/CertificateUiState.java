package org.fox.ttrss.mtls;

import org.fox.ttrss.R;

public final class CertificateUiState {
	private CertificateUiState() {
	}

	public static int summaryRes(ClientCertificateManager.State state) {
		switch (state) {
			case LOADING:
				return R.string.client_certificate_summary_loading;
			case NONE:
				return R.string.client_certificate_summary_none;
			case ERROR:
				return R.string.client_certificate_summary_error;
			case READY:
			default:
				return 0;
		}
	}

	public static boolean canImport(ClientCertificateManager.State state) {
		return state != ClientCertificateManager.State.LOADING;
	}

	public static boolean showRemove(ClientCertificateManager.State state, boolean hasBlob) {
		return state != ClientCertificateManager.State.LOADING && hasBlob;
	}
}
