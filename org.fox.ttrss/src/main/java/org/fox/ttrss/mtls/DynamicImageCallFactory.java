package org.fox.ttrss.mtls;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.preference.PreferenceManager;

import java.io.IOException;
import java.security.GeneralSecurityException;

import kotlin.jvm.functions.Function0;
import kotlin.reflect.KClass;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.EventListener;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okio.Timeout;

public class DynamicImageCallFactory implements Call.Factory {
	private static final class CachedMtlsClient {
		final int generation;
		final OkHttpClient client;

		CachedMtlsClient(int generation, OkHttpClient client) {
			this.generation = generation;
			this.client = client;
		}
	}

	private final SharedPreferences m_prefs;
	private final ImageClientFactory m_factory;
	private final ClientCertificateManager m_manager;
	private volatile CachedMtlsClient m_cachedMtlsClient;

	public DynamicImageCallFactory(Context context, ImageClientFactory factory,
			ClientCertificateManager manager) {
		m_prefs = PreferenceManager.getDefaultSharedPreferences(context.getApplicationContext());
		m_factory = factory;
		m_manager = manager;
	}

	@Override
	public Call newCall(Request request) {
		String ttrssUrl = m_prefs.getString("ttrss_url", "").trim();

		if (!ImageOriginPolicy.isTtrssOrigin(request.url(), ttrssUrl)) {
			return m_factory.plainClient().newCall(request);
		}

		ClientCertificateManager.Snapshot snapshot = m_manager.ensureLoaded();

		switch (m_manager.getState()) {
			case READY:
				try {
					OkHttpClient client = mtlsClient(snapshot);
					return new CrossOriginImageCall(client.newCall(request),
							m_factory.plainClient());
				} catch (GeneralSecurityException e) {
					return new FailingCall(request,
							new IOException("client certificate unavailable", e));
				}
			case ERROR:
				return new FailingCall(request,
						new IOException("client certificate unavailable"));
			case NONE:
			case LOADING:
			default:
				return m_factory.plainClient().newCall(request);
		}
	}

	private OkHttpClient mtlsClient(ClientCertificateManager.Snapshot snapshot)
			throws GeneralSecurityException {
		CachedMtlsClient cached = m_cachedMtlsClient;

		if (cached != null && cached.generation == snapshot.getGeneration()) {
			return cached.client;
		}

		synchronized (this) {
			cached = m_cachedMtlsClient;

			if (cached != null && cached.generation == snapshot.getGeneration()) {
				return cached.client;
			}

			OkHttpClient client = m_factory.mtlsClient(snapshot.getSslContext(),
					MutualTls.trustManager(), this::currentOrigin);
			m_cachedMtlsClient = new CachedMtlsClient(snapshot.getGeneration(), client);

			return client;
		}
	}

	private HttpUrl currentOrigin() {
		return HttpUrl.parse(m_prefs.getString("ttrss_url", "").trim());
	}

	private static class FailingCall implements Call {
		private final Request m_request;
		private final IOException m_failure;
		private final Timeout m_timeout = new Timeout();
		private volatile boolean m_canceled;

		FailingCall(Request request, IOException failure) {
			m_request = request;
			m_failure = failure;
		}

		@Override
		public Request request() {
			return m_request;
		}

		@Override
		public Response execute() throws IOException {
			throw m_failure;
		}

		@Override
		public void enqueue(Callback responseCallback) {
			responseCallback.onFailure(this, m_failure);
		}

		@Override
		public void cancel() {
			m_canceled = true;
		}

		@Override
		public boolean isExecuted() {
			return false;
		}

		@Override
		public boolean isCanceled() {
			return m_canceled;
		}

		@Override
		public Timeout timeout() {
			return m_timeout;
		}

		@Override
		public void addEventListener(EventListener listener) {
		}

		@Override
		public <T> T tag(Class<? extends T> type) {
			return null;
		}

		@Override
		public <T> T tag(KClass<T> type) {
			return null;
		}

		@Override
		public <T> T tag(Class<T> type, Function0<? extends T> defaultValue) {
			return defaultValue.invoke();
		}

		@Override
		public <T> T tag(KClass<T> type, Function0<? extends T> defaultValue) {
			return defaultValue.invoke();
		}

		@Override
		public Call clone() {
			FailingCall clone = new FailingCall(m_request, m_failure);
			clone.m_canceled = m_canceled;
			return clone;
		}
	}
}
