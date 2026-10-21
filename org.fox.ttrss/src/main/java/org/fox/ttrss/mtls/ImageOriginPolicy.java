package org.fox.ttrss.mtls;

import okhttp3.HttpUrl;

public final class ImageOriginPolicy {
	private ImageOriginPolicy() {
	}

	public static boolean isTtrssOrigin(HttpUrl imageUrl, String ttrssUrl) {
		if (imageUrl == null || ttrssUrl == null) return false;

		HttpUrl origin = HttpUrl.parse(ttrssUrl.trim());
		if (origin == null || !origin.isHttps() || !imageUrl.isHttps()) return false;

		return imageUrl.host().equalsIgnoreCase(origin.host())
				&& imageUrl.port() == origin.port();
	}
}
