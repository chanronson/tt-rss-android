package org.fox.ttrss.mtls;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.content.SharedPreferences;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;

import javax.net.ssl.SSLContext;

import okhttp3.Call;
import okhttp3.Interceptor;
import okhttp3.Request;

public class DynamicImageCallFactoryTest {
	private SharedPreferences m_prefs;
	private ClientCertificateManager m_manager;
	private ClientCertificateManager.Snapshot m_snapshot;
	private DynamicImageCallFactory m_factory;
	private Request m_ttrssImage;
	private Request m_otherImage;

	@Before
	public void setUp() throws Exception {
		m_prefs = mock(SharedPreferences.class);
		when(m_prefs.getString("ttrss_url", "")).thenReturn("https://example.com/tt-rss");
		m_manager = mock(ClientCertificateManager.class);
		m_snapshot = new ClientCertificateManager.Snapshot(1, sample(),
				SSLContext.getDefault());
		m_factory = new DynamicImageCallFactory(m_prefs,
				new ImageClientFactory(mock(Interceptor.class)), m_manager);
		m_ttrssImage = new Request.Builder()
				.url("https://example.com/image.png").build();
		m_otherImage = new Request.Builder()
				.url("https://cdn.example.com/image.png").build();
	}

	private ClientCertificate sample() throws Exception {
		try (InputStream in = getClass().getResourceAsStream("/mtls/client-rsa.p12")) {
			return ClientCertificateParser.parse(in.readAllBytes(), "testpass".toCharArray(),
					"client-rsa.p12", System.currentTimeMillis());
		}
	}

	@Test
	public void readyUsesMtlsForTtrssOrigin() {
		when(m_manager.ensureLoaded()).thenReturn(m_snapshot);
		when(m_manager.getState()).thenReturn(ClientCertificateManager.State.READY);

		Call call = m_factory.newCall(m_ttrssImage);

		assertTrue(call instanceof CrossOriginImageCall);
	}

	@Test
	public void noneUsesPlainForTtrssOrigin() {
		when(m_manager.ensureLoaded()).thenReturn(null);
		when(m_manager.getState()).thenReturn(ClientCertificateManager.State.NONE);

		Call call = m_factory.newCall(m_ttrssImage);

		assertFalse(call instanceof CrossOriginImageCall);
	}

	@Test
	public void errorFailsClosedForTtrssOrigin() throws Exception {
		when(m_manager.ensureLoaded()).thenReturn(null);
		when(m_manager.getState()).thenReturn(ClientCertificateManager.State.ERROR);

		Call call = m_factory.newCall(m_ttrssImage);

		try {
			call.execute();
			fail("expected failure");
		} catch (IOException expected) {
			assertTrue(expected.getMessage().contains("client certificate"));
		}
	}

	@Test
	public void otherHostUsesPlainClient() {
		Call call = m_factory.newCall(m_otherImage);

		assertFalse(call instanceof CrossOriginImageCall);
	}
}
