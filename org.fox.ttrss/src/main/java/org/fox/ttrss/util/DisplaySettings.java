package org.fox.ttrss.util;

public class DisplaySettings {
	public static int clampHeadlineFontSize(int base) {
		return Math.max(2, Math.min(21, base));
	}

	public static int headlineTitleSize(int base) {
		return Math.min(21, base + 3);
	}

	public static int headlineSmallSize(int base) {
		return Math.max(10, Math.min(18, base - 2));
	}
}
