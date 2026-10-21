package org.fox.ttrss;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Test;

import java.io.IOException;

import javax.net.ssl.SSLHandshakeException;

import okhttp3.Interceptor;
import okhttp3.Request;

public class ApiCommonRetryTest {
	@Test
	public void sslHandshakeFailureIsNotRetried() throws Exception {
		Interceptor.Chain chain = mock(Interceptor.Chain.class);
		Request request = new Request.Builder().url("https://example.com/").build();

		when(chain.request()).thenReturn(request);
		when(chain.proceed(any(Request.class)))
				.thenThrow(new SSLHandshakeException("bad certificate"));

		try {
			new ApiCommon.RetryInterceptor().intercept(chain);
			fail("expected failure");
		} catch (IOException e) {
			assertTrue(e instanceof SSLHandshakeException);
		}

		verify(chain, times(1)).proceed(any(Request.class));
	}
}
