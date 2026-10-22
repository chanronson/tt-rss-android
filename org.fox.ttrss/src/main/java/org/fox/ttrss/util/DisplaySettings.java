package org.fox.ttrss.util;

public final class DisplaySettings {
	private DisplaySettings() {
	}

	public static int clampHeadlineFontSize(int base) {
		return Math.max(2, Math.min(21, base));
	}

	public static int headlineTitleSize(int base) {
		int clamped = clampHeadlineFontSize(base);
		return Math.min(21, clamped + 3);
	}

	public static int headlineSmallSize(int base) {
		return Math.max(10, Math.min(18, base - 2));
	}

	public static int compactDividerInsetDp(boolean showIcon) {
		return showIcon ? 80 : 16;
	}
}
