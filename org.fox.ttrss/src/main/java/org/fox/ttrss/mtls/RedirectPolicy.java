package org.fox.ttrss.mtls;

import okhttp3.HttpUrl;

public final class RedirectPolicy {
	private RedirectPolicy() {
	}

	public static boolean isRedirect(int code) {
		return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
	}

	public static boolean keepsMethod(int code) {
		return code == 307 || code == 308;
	}

	public static String methodFor(int code, String originalMethod) {
		return keepsMethod(code) ? originalMethod : "GET";
	}

	public static HttpUrl resolve(HttpUrl base, String location) {
		if (base == null || location == null) return null;
		return base.resolve(location);
	}

	public static boolean isSameOrigin(HttpUrl target, HttpUrl origin) {
		return target != null && origin != null
				&& target.scheme().equals(origin.scheme())
				&& target.host().equalsIgnoreCase(origin.host())
				&& target.port() == origin.port();
	}
}
