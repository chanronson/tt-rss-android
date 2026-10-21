package org.fox.ttrss.mtls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;

import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;

public class ClientCertificateManagerTest {
	private ClientCertificateStore m_store;
	private ClientCertificate m_certificate;
	private SSLContext m_sslContext;
	private ClientCertificateManager m_manager;
	private final Executor m_direct = Runnable::run;

	@Before
	public void setUp() throws Exception {
		m_store = mock(ClientCertificateStore.class);
		m_certificate = sample("client-rsa.p12");
		m_sslContext = mock(SSLContext.class);
		m_manager = new ClientCertificateManager(m_store, certificate -> m_sslContext,
				m_direct, m_direct);
	}

	private ClientCertificate sample(String name) throws Exception {
		try (InputStream in = getClass().getResourceAsStream("/mtls/" + name)) {
			assertNotNull(in);
			return ClientCertificateParser.parse(in.readAllBytes(), "testpass".toCharArray(),
					name, System.currentTimeMillis());
		}
	}

	private byte[] fixture(String name) throws Exception {
		try (InputStream in = getClass().getResourceAsStream("/mtls/" + name)) {
			assertNotNull(in);
			return in.readAllBytes();
		}
	}

	private void loadReady() throws Exception {
		when(m_store.load()).thenReturn(m_certificate);
		m_manager.ensureLoaded();
		assertEquals(ClientCertificateManager.State.READY, m_manager.getState());
	}

	@Test
	public void startsLoadingThenNoneWhenNoBlob() throws Exception {
		when(m_store.load()).thenReturn(null);

		assertNull(m_manager.ensureLoaded());
		assertEquals(ClientCertificateManager.State.NONE, m_manager.getState());
	}

	@Test
	public void loadsReadySnapshot() throws Exception {
		loadReady();

		assertNotNull(m_manager.getSnapshot());
		assertEquals(1, m_manager.getSnapshot().getGeneration());
		assertSame(m_certificate, m_manager.getSnapshot().getCertificate());
		assertSame(m_sslContext, m_manager.getSnapshot().getSslContext());
	}

	@Test
	public void loadFailureFailsClosed() throws Exception {
		when(m_store.load()).thenThrow(new StoreException(StoreException.Reason.AUTH, "bad tag"));

		assertNull(m_manager.ensureLoaded());
		assertEquals(ClientCertificateManager.State.ERROR, m_manager.getState());
		assertEquals(StoreException.Reason.AUTH, m_manager.getLastError());

		assertNull(m_manager.ensureLoaded());
		assertEquals(ClientCertificateManager.State.ERROR, m_manager.getState());
		verify(m_store, times(1)).load();
	}

	@Test
	public void importSuccessSwapsSnapshotAndIncrementsGeneration() throws Exception {
		loadReady();
		int oldGeneration = m_manager.getSnapshot().getGeneration();
		AtomicReference<Boolean> success = new AtomicReference<>(false);

		m_manager.importCertificate(fixture("client-ec.p12"), "testpass".toCharArray(),
				"client-ec.p12", new ClientCertificateManager.ImportCallback() {
					@Override
					public void onSuccess() {
						success.set(true);
					}

					@Override
					public void onFailure(CertificateImportException.Reason reason) {
						throw new AssertionError("unexpected failure: " + reason);
					}
				});

		assertEquals(ClientCertificateManager.State.READY, m_manager.getState());
		assertTrue(success.get());
		assertTrue(m_manager.getSnapshot().getGeneration() > oldGeneration);
		verify(m_store).save(any(ClientCertificate.class));
	}

	@Test
	public void importFailureKeepsReadySnapshot() throws Exception {
		loadReady();
		ClientCertificateManager.Snapshot before = m_manager.getSnapshot();
		AtomicReference<CertificateImportException.Reason> failure = new AtomicReference<>();

		m_manager.importCertificate(new byte[]{1, 2, 3}, new char[0], "bad.p12",
				new ClientCertificateManager.ImportCallback() {
					@Override
					public void onSuccess() {
						throw new AssertionError("unexpected success");
					}

					@Override
					public void onFailure(CertificateImportException.Reason reason) {
						failure.set(reason);
					}
				});

		assertEquals(ClientCertificateManager.State.READY, m_manager.getState());
		assertSame(before, m_manager.getSnapshot());
		assertEquals(CertificateImportException.Reason.UNREADABLE, failure.get());
		verify(m_store, never()).save(any(ClientCertificate.class));
	}

	@Test
	public void removeDeletesFileAndKeyThenNone() throws Exception {
		loadReady();
		when(m_store.hasBlob()).thenReturn(true);
		when(m_store.clearFile()).thenReturn(true);
		when(m_store.clearKey()).thenReturn(true);
		AtomicReference<Boolean> keyDeleted = new AtomicReference<>();

		m_manager.remove(new ClientCertificateManager.RemoveCallback() {
			@Override
			public void onSuccess(boolean keyDeletedResult) {
				keyDeleted.set(keyDeletedResult);
			}

			@Override
			public void onFailure(StoreException.Reason reason) {
				throw new AssertionError("unexpected failure: " + reason);
			}
		});

		assertEquals(ClientCertificateManager.State.NONE, m_manager.getState());
		assertNull(m_manager.getSnapshot());
		assertTrue(keyDeleted.get());
	}

	@Test
	public void removeFileFailureKeepsReadyState() throws Exception {
		loadReady();
		ClientCertificateManager.Snapshot before = m_manager.getSnapshot();
		when(m_store.hasBlob()).thenReturn(true);
		when(m_store.clearFile()).thenReturn(false);
		AtomicReference<StoreException.Reason> failure = new AtomicReference<>();

		m_manager.remove(new ClientCertificateManager.RemoveCallback() {
			@Override
			public void onSuccess(boolean keyDeletedResult) {
				throw new AssertionError("unexpected success");
			}

			@Override
			public void onFailure(StoreException.Reason reason) {
				failure.set(reason);
			}
		});

		assertEquals(ClientCertificateManager.State.READY, m_manager.getState());
		assertSame(before, m_manager.getSnapshot());
		assertEquals(StoreException.Reason.IO, failure.get());
		verify(m_store, never()).clearKey();
	}

	@Test
	public void removeFileFailureKeepsErrorState() throws Exception {
		when(m_store.load()).thenThrow(new StoreException(StoreException.Reason.AUTH, "bad tag"));
		m_manager.ensureLoaded();
		when(m_store.hasBlob()).thenReturn(true);
		when(m_store.clearFile()).thenReturn(false);

		m_manager.remove(new ClientCertificateManager.RemoveCallback() {
			@Override
			public void onSuccess(boolean keyDeletedResult) {
				throw new AssertionError("unexpected success");
			}

			@Override
			public void onFailure(StoreException.Reason reason) {
			}
		});

		assertEquals(ClientCertificateManager.State.ERROR, m_manager.getState());
		assertEquals(StoreException.Reason.AUTH, m_manager.getLastError());
	}

	@Test
	public void removeKeyFailureSwapsNoneAndReportsKeyDeletedFalse() throws Exception {
		loadReady();
		when(m_store.hasBlob()).thenReturn(true);
		when(m_store.clearFile()).thenReturn(true);
		when(m_store.clearKey()).thenReturn(false);
		AtomicReference<Boolean> keyDeleted = new AtomicReference<>();

		m_manager.remove(new ClientCertificateManager.RemoveCallback() {
			@Override
			public void onSuccess(boolean keyDeletedResult) {
				keyDeleted.set(keyDeletedResult);
			}

			@Override
			public void onFailure(StoreException.Reason reason) {
				throw new AssertionError("unexpected failure: " + reason);
			}
		});

		assertEquals(ClientCertificateManager.State.NONE, m_manager.getState());
		assertEquals(false, keyDeleted.get());
	}

	@Test
	public void singleFlightLoadsOnce() throws Exception {
		AtomicInteger calls = new AtomicInteger();
		when(m_store.load()).thenAnswer(invocation -> {
			calls.incrementAndGet();
			Thread.sleep(100);
			return m_certificate;
		});

		ExecutorService pool = Executors.newFixedThreadPool(2);
		CountDownLatch start = new CountDownLatch(1);
		Callable<Void> task = () -> {
			start.await();
			m_manager.ensureLoaded();
			return null;
		};

		Future<?> first = pool.submit(task);
		Future<?> second = pool.submit(task);
		start.countDown();
		first.get(5, TimeUnit.SECONDS);
		second.get(5, TimeUnit.SECONDS);
		pool.shutdown();

		assertEquals(1, calls.get());
		assertEquals(ClientCertificateManager.State.READY, m_manager.getState());
	}

	@Test
	public void loadOverlappingImportIsSerialized() throws Exception {
		CountDownLatch entered = new CountDownLatch(1);
		CountDownLatch release = new CountDownLatch(1);
		when(m_store.load()).thenAnswer(invocation -> {
			entered.countDown();
			release.await(5, TimeUnit.SECONDS);
			return m_certificate;
		});

		ExecutorService pool = Executors.newFixedThreadPool(2);
		Future<?> load = pool.submit(() -> {
			m_manager.ensureLoaded();
			return null;
		});
		assertTrue(entered.await(5, TimeUnit.SECONDS));

		Future<?> importFuture = pool.submit(() -> {
			m_manager.importCertificate(fixture("client-rsa.p12"), "testpass".toCharArray(),
					"client-rsa.p12", new ClientCertificateManager.ImportCallback() {
						@Override
						public void onSuccess() {
						}

						@Override
						public void onFailure(CertificateImportException.Reason reason) {
							throw new AssertionError("unexpected failure: " + reason);
						}
					});
			return null;
		});

		Thread.sleep(50);
		release.countDown();
		load.get(5, TimeUnit.SECONDS);
		importFuture.get(5, TimeUnit.SECONDS);
		pool.shutdown();

		assertEquals(ClientCertificateManager.State.READY, m_manager.getState());
		verify(m_store).save(any(ClientCertificate.class));
	}

	@Test
	public void listenerGetsCurrentStateImmediately() throws Exception {
		when(m_store.load()).thenReturn(null);
		m_manager.ensureLoaded();
		List<ClientCertificateManager.State> states = new ArrayList<>();

		m_manager.addListener(states::add);

		assertEquals(Arrays.asList(ClientCertificateManager.State.NONE), states);
	}

	@Test
	public void listenerNotifiedOnEveryTransition() throws Exception {
		when(m_store.load()).thenReturn(m_certificate);
		when(m_store.hasBlob()).thenReturn(true);
		when(m_store.clearFile()).thenReturn(true);
		when(m_store.clearKey()).thenReturn(true);
		List<ClientCertificateManager.State> states = new ArrayList<>();
		m_manager.addListener(states::add);

		m_manager.ensureLoaded();
		m_manager.importCertificate(fixture("client-rsa.p12"), "testpass".toCharArray(),
				"client-rsa.p12", new ClientCertificateManager.ImportCallback() {
					@Override
					public void onSuccess() {
					}

					@Override
					public void onFailure(CertificateImportException.Reason reason) {
					}
				});
		m_manager.remove(new ClientCertificateManager.RemoveCallback() {
			@Override
			public void onSuccess(boolean keyDeleted) {
			}

			@Override
			public void onFailure(StoreException.Reason reason) {
			}
		});

		assertEquals(Arrays.asList(
				ClientCertificateManager.State.LOADING,
				ClientCertificateManager.State.READY,
				ClientCertificateManager.State.READY,
				ClientCertificateManager.State.NONE), states);
	}
}
