package org.fox.ttrss;

import static org.junit.Assert.*;

import org.fox.ttrss.util.DisplaySettings;
import org.junit.Test;

public class DisplaySettingsTest {
	@Test
	public void headlineFontSizeClampsTo2to21() {
		assertEquals(2, DisplaySettings.clampHeadlineFontSize(0));
		assertEquals(2, DisplaySettings.clampHeadlineFontSize(2));
		assertEquals(13, DisplaySettings.clampHeadlineFontSize(13));
		assertEquals(21, DisplaySettings.clampHeadlineFontSize(21));
		assertEquals(21, DisplaySettings.clampHeadlineFontSize(99));
	}

	@Test
	public void headlineDerivedSizesMatchExistingFormulas() {
		assertEquals(5, DisplaySettings.headlineTitleSize(2));
		assertEquals(16, DisplaySettings.headlineTitleSize(13));
		assertEquals(21, DisplaySettings.headlineTitleSize(21));
		assertEquals(10, DisplaySettings.headlineSmallSize(2));
		assertEquals(11, DisplaySettings.headlineSmallSize(13));
		assertEquals(18, DisplaySettings.headlineSmallSize(21));
	}

	@Test
	public void compactDividerInsetFollowsIconVisibility() {
		assertEquals(80, DisplaySettings.compactDividerInsetDp(true));
		assertEquals(16, DisplaySettings.compactDividerInsetDp(false));
	}
}
