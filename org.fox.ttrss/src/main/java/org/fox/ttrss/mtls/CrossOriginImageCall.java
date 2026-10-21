package org.fox.ttrss.mtls;

import java.io.IOException;

import kotlin.jvm.functions.Function0;
import kotlin.reflect.KClass;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.EventListener;
import okhttp3.HttpUrl;
import okhttp3.Request;
import okhttp3.Response;
import okio.Timeout;

public class CrossOriginImageCall implements Call {
	private final Call m_delegate;
	private final Call.Factory m_plainFactory;
	private volatile Call m_plainCall;

	public CrossOriginImageCall(Call delegate, Call.Factory plainFactory) {
		m_delegate = delegate;
		m_plainFactory = plainFactory;
	}

	@Override
	public Request request() {
		return m_delegate.request();
	}

	@Override
	public Response execute() throws IOException {
		Response response = m_delegate.execute();

		if (!isBlocked(response)) return response;

		Request next = redirectedRequest(response);

		if (next == null) return response;

		response.close();

		Call plainCall = m_plainFactory.newCall(next);
		m_plainCall = plainCall;

		return plainCall.execute();
	}

	@Override
	public void enqueue(Callback callback) {
		m_delegate.enqueue(new Callback() {
			@Override
			public void onFailure(Call call, IOException e) {
				callback.onFailure(CrossOriginImageCall.this, e);
			}

			@Override
			public void onResponse(Call call, Response response) throws IOException {
				if (!isBlocked(response)) {
					callback.onResponse(CrossOriginImageCall.this, response);
					return;
				}

				Request next = redirectedRequest(response);

				if (next == null) {
					callback.onResponse(CrossOriginImageCall.this, response);
					return;
				}

				response.close();

				Call plainCall = m_plainFactory.newCall(next);
				m_plainCall = plainCall;
				plainCall.enqueue(new Callback() {
					@Override
					public void onFailure(Call call, IOException e) {
						callback.onFailure(CrossOriginImageCall.this, e);
					}

					@Override
					public void onResponse(Call call, Response response) throws IOException {
						callback.onResponse(CrossOriginImageCall.this, response);
					}
				});
			}
		});
	}

	@Override
	public void cancel() {
		m_delegate.cancel();

		Call plainCall = m_plainCall;
		if (plainCall != null) plainCall.cancel();
	}

	@Override
	public boolean isExecuted() {
		return m_delegate.isExecuted();
	}

	@Override
	public boolean isCanceled() {
		return m_delegate.isCanceled();
	}

	@Override
	public Timeout timeout() {
		return m_delegate.timeout();
	}

	@Override
	public void addEventListener(EventListener listener) {
		m_delegate.addEventListener(listener);
	}

	@Override
	public <T> T tag(Class<? extends T> type) {
		return m_delegate.tag(type);
	}

	@Override
	public <T> T tag(KClass<T> type) {
		return m_delegate.tag(type);
	}

	@Override
	public <T> T tag(Class<T> type, Function0<? extends T> defaultValue) {
		return m_delegate.tag(type, defaultValue);
	}

	@Override
	public <T> T tag(KClass<T> type, Function0<? extends T> defaultValue) {
		return m_delegate.tag(type, defaultValue);
	}

	@Override
	public Call clone() {
		return new CrossOriginImageCall(m_delegate.clone(), m_plainFactory);
	}

	private static boolean isBlocked(Response response) {
		return response != null
				&& RedirectPolicy.isRedirect(response.code())
				&& response.header(SameOriginRedirectInterceptor.HEADER_REDIRECT_BLOCKED) != null;
	}

	private static Request redirectedRequest(Response response) {
		HttpUrl target = RedirectPolicy.resolve(response.request().url(),
				response.header("Location"));

		if (target == null) return null;

		Request.Builder builder = response.request().newBuilder().url(target);

		if (!RedirectPolicy.keepsMethod(response.code())) {
			builder.method("GET", null);
			builder.removeHeader("Content-Type");
			builder.removeHeader("Content-Length");
		}

		return builder.build();
	}
}
