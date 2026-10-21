package org.fox.ttrss.mtls;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import okhttp3.HttpUrl;

public class ImageOriginPolicyTest {
	@Test
	public void sameOriginMatches() {
		assertTrue(ImageOriginPolicy.isTtrssOrigin(
				HttpUrl.parse("https://example.com/images/a.png"),
				"https://example.com/tt-rss"));
	}

	@Test
	public void explicitDefaultPortMatches() {
		assertTrue(ImageOriginPolicy.isTtrssOrigin(
				HttpUrl.parse("https://example.com:443/images/a.png"),
				"https://example.com/tt-rss"));
	}

	@Test
	public void otherHostDoesNotMatch() {
		assertFalse(ImageOriginPolicy.isTtrssOrigin(
				HttpUrl.parse("https://cdn.example.com/a.png"),
				"https://example.com/tt-rss"));
	}

	@Test
	public void otherSchemeDoesNotMatch() {
		assertFalse(ImageOriginPolicy.isTtrssOrigin(
				HttpUrl.parse("http://example.com/a.png"),
				"https://example.com/tt-rss"));
	}

	@Test
	public void otherPortDoesNotMatch() {
		assertFalse(ImageOriginPolicy.isTtrssOrigin(
				HttpUrl.parse("https://example.com:8443/a.png"),
				"https://example.com/tt-rss"));
	}

	@Test
	public void pathAndQueryDoNotMatter() {
		assertTrue(ImageOriginPolicy.isTtrssOrigin(
				HttpUrl.parse("https://example.com/other/a.png?x=1"),
				"https://example.com/tt-rss?y=2"));
	}

	@Test
	public void invalidTtrssUrlDoesNotMatch() {
		assertFalse(ImageOriginPolicy.isTtrssOrigin(
				HttpUrl.parse("https://example.com/a.png"), "not a url"));
	}

	@Test
	public void httpImageDoesNotMatch() {
		assertFalse(ImageOriginPolicy.isTtrssOrigin(
				HttpUrl.parse("http://example.com/a.png"),
				"http://example.com/tt-rss"));
	}
}
