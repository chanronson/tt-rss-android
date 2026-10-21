package org.fox.ttrss.mtls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.MediaType;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

public class SameOriginRedirectInterceptorTest {
	private static final MediaType JSON = MediaType.parse("application/json");

	private Response response(Request request, int code, String location) {
		Response.Builder builder = new Response.Builder()
				.request(request)
				.protocol(Protocol.HTTP_1_1)
				.code(code)
				.message("response")
				.body(ResponseBody.create("", MediaType.parse("text/plain")));

		if (location != null) builder.header("Location", location);

		return builder.build();
	}

	@Test
	public void sameOrigin302FollowsWithGet() throws IOException {
		Interceptor.Chain chain = mock(Interceptor.Chain.class);
		Request initial = new Request.Builder()
				.url("https://example.com/tt-rss/api/")
				.post(RequestBody.create("payload", JSON))
				.build();

		when(chain.request()).thenReturn(initial);
		when(chain.proceed(any(Request.class))).thenAnswer(invocation -> {
			Request request = invocation.getArgument(0);
			if (request.url().encodedPath().equals("/tt-rss/api/")) {
				return response(request, 302, "https://example.com/tt-rss/api/v2/");
			}
			return response(request, 200, null);
		});

		SameOriginRedirectInterceptor interceptor = new SameOriginRedirectInterceptor(
				() -> HttpUrl.parse("https://example.com/tt-rss"));

		Response result = interceptor.intercept(chain);

		assertEquals(200, result.code());
		ArgumentCaptor<Request> captor = ArgumentCaptor.forClass(Request.class);
		verify(chain, times(2)).proceed(captor.capture());
		assertEquals("GET", captor.getAllValues().get(1).method());
		assertNull(captor.getAllValues().get(1).body());
	}

	@Test
	public void replayRedirectKeepsBody() throws IOException {
		Interceptor.Chain chain = mock(Interceptor.Chain.class);
		RequestBody body = RequestBody.create("payload", JSON);
		Request initial = new Request.Builder()
				.url("https://example.com/tt-rss/api/")
				.post(body)
				.build();

		when(chain.request()).thenReturn(initial);
		when(chain.proceed(any(Request.class))).thenAnswer(invocation -> {
			Request request = invocation.getArgument(0);
			if (request.url().encodedPath().equals("/tt-rss/api/")) {
				return response(request, 307, "/tt-rss/api/v2/");
			}
			return response(request, 200, null);
		});

		SameOriginRedirectInterceptor interceptor = new SameOriginRedirectInterceptor(
				() -> HttpUrl.parse("https://example.com/tt-rss"));

		Response result = interceptor.intercept(chain);

		assertEquals(200, result.code());
		ArgumentCaptor<Request> captor = ArgumentCaptor.forClass(Request.class);
		verify(chain, times(2)).proceed(captor.capture());
		assertEquals("POST", captor.getAllValues().get(1).method());
		assertNotNull(captor.getAllValues().get(1).body());
	}

	@Test
	public void crossOriginRedirectIsBlocked() throws IOException {
		Interceptor.Chain chain = mock(Interceptor.Chain.class);
		Request initial = new Request.Builder()
				.url("https://example.com/tt-rss/api/")
				.get()
				.build();

		when(chain.request()).thenReturn(initial);
		when(chain.proceed(any(Request.class))).thenAnswer(invocation ->
				response(invocation.getArgument(0), 302, "https://evil.example/steal"));

		SameOriginRedirectInterceptor interceptor = new SameOriginRedirectInterceptor(
				() -> HttpUrl.parse("https://example.com/tt-rss"));

		Response result = interceptor.intercept(chain);

		assertEquals(302, result.code());
		assertEquals("1", result.header(SameOriginRedirectInterceptor.HEADER_REDIRECT_BLOCKED));
		verify(chain, times(1)).proceed(any(Request.class));
	}

	@Test
	public void redirectLimitBlocksAfterFive() throws IOException {
		Interceptor.Chain chain = mock(Interceptor.Chain.class);
		Request initial = new Request.Builder()
				.url("https://example.com/tt-rss/api/0")
				.get()
				.build();

		when(chain.request()).thenReturn(initial);
		when(chain.proceed(any(Request.class))).thenAnswer(invocation -> {
			Request request = invocation.getArgument(0);
			int index = Integer.parseInt(request.url().encodedPath().substring(
					request.url().encodedPath().length() - 1));
			return response(request, 302, "/tt-rss/api/" + (index + 1));
		});

		SameOriginRedirectInterceptor interceptor = new SameOriginRedirectInterceptor(
				() -> HttpUrl.parse("https://example.com/tt-rss"));

		Response result = interceptor.intercept(chain);

		assertEquals(302, result.code());
		assertEquals("1", result.header(SameOriginRedirectInterceptor.HEADER_REDIRECT_BLOCKED));
		verify(chain, times(6)).proceed(any(Request.class));
	}

	@Test
	public void originSupplierReadsAgainForEachRedirect() throws IOException {
		Interceptor.Chain chain = mock(Interceptor.Chain.class);
		Request initial = new Request.Builder()
				.url("https://example.com/tt-rss/api/0")
				.get()
				.build();

		when(chain.request()).thenReturn(initial);
		when(chain.proceed(any(Request.class))).thenAnswer(invocation -> {
			Request request = invocation.getArgument(0);
			if (request.url().encodedPath().endsWith("/0")) {
				return response(request, 302, "/tt-rss/api/1");
			}
			return response(request, 302, "/tt-rss/api/2");
		});

		AtomicInteger calls = new AtomicInteger();
		SameOriginRedirectInterceptor interceptor = new SameOriginRedirectInterceptor(() -> {
			if (calls.getAndIncrement() == 0) {
				return HttpUrl.parse("https://example.com/tt-rss");
			}
			return HttpUrl.parse("https://other.example/tt-rss");
		});

		Response result = interceptor.intercept(chain);

		assertEquals(302, result.code());
		assertNotNull(result.header(SameOriginRedirectInterceptor.HEADER_REDIRECT_BLOCKED));
		verify(chain, times(2)).proceed(any(Request.class));
	}
}
