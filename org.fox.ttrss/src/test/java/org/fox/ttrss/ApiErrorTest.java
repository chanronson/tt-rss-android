package org.fox.ttrss;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import org.fox.ttrss.ApiCommon.ApiError;

public class ApiErrorTest {
	@Test
	public void certificateErrorMapsToResource() {
		assertEquals(R.string.error_client_certificate,
				ApiCommon.getErrorMessage(ApiError.CLIENT_CERTIFICATE_ERROR));
	}

	@Test
	public void redirectBlockedMapsToResource() {
		assertEquals(R.string.error_redirect_blocked,
				ApiCommon.getErrorMessage(ApiError.REDIRECT_BLOCKED));
	}

	@Test
	public void sslRejectedMapsToResource() {
		assertEquals(R.string.error_ssl_rejected,
				ApiCommon.getErrorMessage(ApiError.SSL_REJECTED));
	}
}
