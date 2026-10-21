package org.fox.ttrss.mtls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import okhttp3.HttpUrl;

public class RedirectPolicyTest {
	@Test
	public void mappingRedirectsUseGet() {
		assertEquals("GET", RedirectPolicy.methodFor(301, "POST"));
		assertEquals("GET", RedirectPolicy.methodFor(302, "POST"));
		assertEquals("GET", RedirectPolicy.methodFor(303, "POST"));
	}

	@Test
	public void replayRedirectsKeepMethod() {
		assertTrue(RedirectPolicy.keepsMethod(307));
		assertTrue(RedirectPolicy.keepsMethod(308));
		assertEquals("POST", RedirectPolicy.methodFor(307, "POST"));
		assertEquals("POST", RedirectPolicy.methodFor(308, "POST"));
	}

	@Test
	public void recognizedRedirectCodes() {
		assertTrue(RedirectPolicy.isRedirect(301));
		assertTrue(RedirectPolicy.isRedirect(302));
		assertTrue(RedirectPolicy.isRedirect(303));
		assertTrue(RedirectPolicy.isRedirect(307));
		assertTrue(RedirectPolicy.isRedirect(308));
		assertFalse(RedirectPolicy.isRedirect(304));
		assertFalse(RedirectPolicy.isRedirect(200));
	}

	@Test
	public void relativeLocationResolves() {
		HttpUrl base = HttpUrl.parse("https://example.com/tt-rss/api/");
		assertNotNull(base);
		HttpUrl target = RedirectPolicy.resolve(base, "../api/v2/");
		assertNotNull(target);
		assertEquals("/tt-rss/api/v2/", target.encodedPath());
	}

	@Test
	public void sameOriginUsesSchemeHostAndEffectivePort() {
		HttpUrl origin = HttpUrl.parse("https://example.com/tt-rss");

		assertTrue(RedirectPolicy.isSameOrigin(
				HttpUrl.parse("https://example.com:443/tt-rss/api/"), origin));
		assertTrue(RedirectPolicy.isSameOrigin(
				HttpUrl.parse("https://example.com/other"), origin));

		assertFalse(RedirectPolicy.isSameOrigin(
				HttpUrl.parse("http://example.com/tt-rss"), origin));
		assertFalse(RedirectPolicy.isSameOrigin(
				HttpUrl.parse("https://other.example.com/tt-rss"), origin));
		assertFalse(RedirectPolicy.isSameOrigin(
				HttpUrl.parse("https://example.com:8443/tt-rss"), origin));
	}
}
