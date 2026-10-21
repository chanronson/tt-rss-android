package org.fox.ttrss.mtls;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ApiClientSelectorTest {
	@Test
	public void noneUsesPlainForHttps() {
		assertEquals(ApiClientSelector.Mode.PLAIN,
				ApiClientSelector.select(ClientCertificateManager.State.NONE,
						"https://example.com/tt-rss"));
	}

	@Test
	public void readyUsesMtlsForHttps() {
		assertEquals(ApiClientSelector.Mode.MTLS,
				ApiClientSelector.select(ClientCertificateManager.State.READY,
						"https://example.com/tt-rss"));
	}

	@Test
	public void readyUsesPlainForHttp() {
		assertEquals(ApiClientSelector.Mode.PLAIN,
				ApiClientSelector.select(ClientCertificateManager.State.READY,
						"http://example.com/tt-rss"));
	}

	@Test
	public void errorAlwaysFails() {
		assertEquals(ApiClientSelector.Mode.ERROR,
				ApiClientSelector.select(ClientCertificateManager.State.ERROR,
						"https://example.com/tt-rss"));
	}

	@Test
	public void loadingFailsClosed() {
		assertEquals(ApiClientSelector.Mode.ERROR,
				ApiClientSelector.select(ClientCertificateManager.State.LOADING,
						"https://example.com/tt-rss"));
	}

	@Test
	public void invalidUrlUsesPlain() {
		assertEquals(ApiClientSelector.Mode.PLAIN,
				ApiClientSelector.select(ClientCertificateManager.State.READY, "not a url"));
	}
}
