package org.fox.ttrss.mtls;

import java.io.IOException;
import java.util.function.Supplier;

import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

public class SameOriginRedirectInterceptor implements Interceptor {
	public static final String HEADER_REDIRECT_BLOCKED = "X-TT-RSS-Redirect-Blocked";
	private static final int MAX_REDIRECTS = 5;

	private final Supplier<HttpUrl> m_originSupplier;

	public SameOriginRedirectInterceptor(Supplier<HttpUrl> originSupplier) {
		m_originSupplier = originSupplier;
	}

	@Override
	public Response intercept(Chain chain) throws IOException {
		Request request = chain.request();
		Response response = chain.proceed(request);
		int redirects = 0;

		while (RedirectPolicy.isRedirect(response.code())) {
			if (redirects >= MAX_REDIRECTS) return block(response);

			HttpUrl target = RedirectPolicy.resolve(response.request().url(),
					response.header("Location"));
			HttpUrl origin = m_originSupplier.get();

			if (target == null || origin == null
					|| !RedirectPolicy.isSameOrigin(target, origin)) {
				return block(response);
			}

			Request.Builder builder = request.newBuilder().url(target);

			if (!RedirectPolicy.keepsMethod(response.code())) {
				builder.method("GET", null);
				builder.removeHeader("Content-Type");
				builder.removeHeader("Content-Length");
			} else if (request.body() != null && request.body().isOneShot()) {
				return block(response);
			}

			Request next = builder.build();
			Response previous = response;
			request = next;

			try {
				response = chain.proceed(next);
			} finally {
				previous.close();
			}

			redirects++;
		}

		return response;
	}

	private static Response block(Response response) {
		return response.newBuilder()
				.header(HEADER_REDIRECT_BLOCKED, "1")
				.build();
	}
}
