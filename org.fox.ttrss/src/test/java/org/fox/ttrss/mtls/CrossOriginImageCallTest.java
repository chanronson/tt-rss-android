package org.fox.ttrss.mtls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.io.IOException;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.HttpUrl;
import okhttp3.Request;
import okhttp3.Response;

public class CrossOriginImageCallTest {
	@Test
	public void crossOriginRetryUsesPlainClient() throws Exception {
		Request request = new Request.Builder().url("https://example.com/image.png").build();
		Response blocked = mock(Response.class);
		Response plainResponse = mock(Response.class);
		Call delegate = mock(Call.class);
		Call.Factory plainFactory = mock(Call.Factory.class);
		Call plainCall = mock(Call.class);

		when(blocked.code()).thenReturn(302);
		when(blocked.header(SameOriginRedirectInterceptor.HEADER_REDIRECT_BLOCKED)).thenReturn("1");
		when(blocked.header("Location")).thenReturn("https://cdn.example/image.png");
		when(blocked.request()).thenReturn(request);
		when(delegate.execute()).thenReturn(blocked);
		when(plainFactory.newCall(any(Request.class))).thenReturn(plainCall);
		when(plainCall.execute()).thenReturn(plainResponse);

		CrossOriginImageCall call = new CrossOriginImageCall(delegate, plainFactory);
		Response result = call.execute();

		assertSame(plainResponse, result);
		verify(blocked).close();

		ArgumentCaptor<Request> captor = ArgumentCaptor.forClass(Request.class);
		verify(plainFactory).newCall(captor.capture());
		assertEquals(HttpUrl.parse("https://cdn.example/image.png"), captor.getValue().url());
	}

	@Test
	public void nonBlockedResponseReturnsUnchanged() throws Exception {
		Response normal = mock(Response.class);
		Call delegate = mock(Call.class);
		Call.Factory plainFactory = mock(Call.Factory.class);

		when(normal.code()).thenReturn(200);
		when(delegate.execute()).thenReturn(normal);

		CrossOriginImageCall call = new CrossOriginImageCall(delegate, plainFactory);

		assertSame(normal, call.execute());
		verify(plainFactory, never()).newCall(any(Request.class));
	}

	@Test
	public void cancelCancelsDelegateAndPlainCall() throws Exception {
		Request request = new Request.Builder().url("https://example.com/image.png").build();
		Response blocked = mock(Response.class);
		Response plainResponse = mock(Response.class);
		Call delegate = mock(Call.class);
		Call.Factory plainFactory = mock(Call.Factory.class);
		Call plainCall = mock(Call.class);

		when(blocked.code()).thenReturn(302);
		when(blocked.header(SameOriginRedirectInterceptor.HEADER_REDIRECT_BLOCKED)).thenReturn("1");
		when(blocked.header("Location")).thenReturn("/cdn/image.png");
		when(blocked.request()).thenReturn(request);
		when(delegate.execute()).thenReturn(blocked);
		when(plainFactory.newCall(any(Request.class))).thenReturn(plainCall);
		when(plainCall.execute()).thenReturn(plainResponse);

		CrossOriginImageCall call = new CrossOriginImageCall(delegate, plainFactory);
		call.execute();
		call.cancel();

		verify(delegate).cancel();
		verify(plainCall).cancel();
	}

	@Test
	public void enqueueForwardsFailure() {
		Call delegate = mock(Call.class);
		Call.Factory plainFactory = mock(Call.Factory.class);
		Callback callback = mock(Callback.class);
		IOException failure = new IOException("boom");
		CrossOriginImageCall call = new CrossOriginImageCall(delegate, plainFactory);

		call.enqueue(callback);

		ArgumentCaptor<Callback> captor = ArgumentCaptor.forClass(Callback.class);
		verify(delegate).enqueue(captor.capture());
		captor.getValue().onFailure(delegate, failure);

		verify(callback).onFailure(call, failure);
	}
}
