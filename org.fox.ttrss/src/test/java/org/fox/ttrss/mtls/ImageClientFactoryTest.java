package org.fox.ttrss.mtls;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import org.junit.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;

public class ImageClientFactoryTest {
	@Test
	public void bothClientsUseProgressInterceptor() throws Exception {
		Interceptor progress = mock(Interceptor.class);
		ImageClientFactory factory = new ImageClientFactory(progress);

		OkHttpClient plain = factory.plainClient();
		X509TrustManager trustManager = MutualTls.trustManager();
		OkHttpClient mtls = factory.mtlsClient(SSLContext.getDefault(), trustManager,
				() -> HttpUrl.parse("https://example.com/tt-rss"));

		assertTrue(plain.networkInterceptors().contains(progress));
		assertTrue(mtls.networkInterceptors().contains(progress));
	}

	@Test
	public void mtlsClientDisablesRedirects() throws Exception {
		ImageClientFactory factory = new ImageClientFactory(mock(Interceptor.class));

		OkHttpClient mtls = factory.mtlsClient(SSLContext.getDefault(),
				MutualTls.trustManager(), () -> HttpUrl.parse("https://example.com/tt-rss"));

		assertFalse(mtls.followRedirects());
		assertFalse(mtls.followSslRedirects());
	}
}
