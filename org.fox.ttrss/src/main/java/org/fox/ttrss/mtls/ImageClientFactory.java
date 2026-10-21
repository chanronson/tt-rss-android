package org.fox.ttrss.mtls;

import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.X509TrustManager;

import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;

public class ImageClientFactory {
	private final Interceptor m_progressInterceptor;
	private volatile OkHttpClient m_plainClient;

	public ImageClientFactory(Interceptor progressInterceptor) {
		m_progressInterceptor = progressInterceptor;
	}

	public OkHttpClient plainClient() {
		OkHttpClient client = m_plainClient;

		if (client == null) {
			synchronized (this) {
				client = m_plainClient;

				if (client == null) {
					client = baseBuilder()
							.addNetworkInterceptor(m_progressInterceptor)
							.build();
					m_plainClient = client;
				}
			}
		}

		return client;
	}

	public OkHttpClient mtlsClient(SSLContext context, X509TrustManager trustManager,
			Supplier<HttpUrl> originSupplier) {
		return baseBuilder()
				.sslSocketFactory(MutualTls.socketFactory(context), trustManager)
				.followRedirects(false)
				.followSslRedirects(false)
				.addInterceptor(new SameOriginRedirectInterceptor(originSupplier))
				.addNetworkInterceptor(m_progressInterceptor)
				.build();
	}

	private static OkHttpClient.Builder baseBuilder() {
		return new OkHttpClient.Builder()
				.connectTimeout(10, TimeUnit.SECONDS)
				.writeTimeout(10, TimeUnit.SECONDS)
				.readTimeout(30, TimeUnit.SECONDS);
	}
}
