package org.fox.ttrss.mtls;

import android.content.Context;

import androidx.core.content.ContextCompat;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.net.ssl.SSLContext;

public class ClientCertificateManager {
	public enum State {
		LOADING,
		NONE,
		READY,
		ERROR
	}

	public interface Listener {
		void onStateChanged(State state);
	}

	public interface ImportCallback {
		void onSuccess();

		void onFailure(CertificateImportException.Reason reason);
	}

	public interface RemoveCallback {
		void onSuccess(boolean keyDeleted);

		void onFailure(StoreException.Reason reason);
	}

	public interface SslContextFactory {
		SSLContext create(ClientCertificate certificate) throws GeneralSecurityException;
	}

	public static final class Snapshot {
		private final int m_generation;
		private final ClientCertificate m_certificate;
		private final SSLContext m_sslContext;

		Snapshot(int generation, ClientCertificate certificate, SSLContext sslContext) {
			m_generation = generation;
			m_certificate = certificate;
			m_sslContext = sslContext;
		}

		public int getGeneration() {
			return m_generation;
		}

		public ClientCertificate getCertificate() {
			return m_certificate;
		}

		public SSLContext getSslContext() {
			return m_sslContext;
		}
	}

	private static final Object INSTANCE_LOCK = new Object();
	private static ClientCertificateManager sInstance;

	private final Object m_lock = new Object();
	private final CopyOnWriteArrayList<Listener> m_listeners = new CopyOnWriteArrayList<>();

	private ClientCertificateStore m_store;
	private SslContextFactory m_sslContextFactory;
	private Executor m_executor;
	private Executor m_callbackExecutor;

	private State m_state = State.LOADING;
	private Snapshot m_snapshot;
	private StoreException.Reason m_lastError;
	private int m_generation;
	private boolean m_initialized;

	private ClientCertificateManager() {
	}

	ClientCertificateManager(ClientCertificateStore store, SslContextFactory sslContextFactory,
			Executor executor, Executor callbackExecutor) {
		m_store = store;
		m_sslContextFactory = sslContextFactory;
		m_executor = executor;
		m_callbackExecutor = callbackExecutor;
		m_initialized = true;
	}

	public static ClientCertificateManager getInstance() {
		synchronized (INSTANCE_LOCK) {
			if (sInstance == null) sInstance = new ClientCertificateManager();
			return sInstance;
		}
	}

	public void initialize(Context context, SslContextFactory sslContextFactory) {
		synchronized (m_lock) {
			if (m_initialized) return;

			m_store = ClientCertificateStore.create(context);
			m_sslContextFactory = sslContextFactory;
			m_executor = Executors.newSingleThreadExecutor();
			m_callbackExecutor = ContextCompat.getMainExecutor(context);
			m_initialized = true;
		}

		startLoad();
	}

	public void startLoad() {
		Executor executor;

		synchronized (m_lock) {
			executor = m_executor;
		}

		if (executor != null) executor.execute(this::ensureLoaded);
	}

	public Snapshot ensureLoaded() {
		boolean changed;

		synchronized (m_lock) {
			changed = ensureLoadedLocked();
		}

		if (changed) notifyListeners();

		synchronized (m_lock) {
			return m_snapshot;
		}
	}

	public State getState() {
		synchronized (m_lock) {
			return m_state;
		}
	}

	public Snapshot getSnapshot() {
		synchronized (m_lock) {
			return m_snapshot;
		}
	}

	public StoreException.Reason getLastError() {
		synchronized (m_lock) {
			return m_lastError;
		}
	}

	public boolean hasBlob() {
		synchronized (m_lock) {
			return m_store != null && m_store.hasBlob();
		}
	}

	public void importCertificate(byte[] pkcs12, char[] password, String displayName,
			ImportCallback callback) {
		byte[] data = pkcs12 == null ? new byte[0] : Arrays.copyOf(pkcs12, pkcs12.length);
		char[] pass = password == null ? new char[0] : Arrays.copyOf(password, password.length);

		Runnable task = () -> {
			CertificateImportException.Reason failure = null;
			boolean changed = false;

			synchronized (m_lock) {
				if (ensureLoadedLocked()) changed = true;

				State previousState = m_state;
				Snapshot previousSnapshot = m_snapshot;

				try {
					ClientCertificate certificate = ClientCertificateParser.parse(data, pass,
							displayName, System.currentTimeMillis());

					if (m_sslContextFactory == null) {
						throw new GeneralSecurityException("no SSL context factory");
					}

					SSLContext sslContext = m_sslContextFactory.create(certificate);
					m_store.save(certificate);

					m_snapshot = new Snapshot(++m_generation, certificate, sslContext);
					m_state = State.READY;
					m_lastError = null;
					changed = true;
				} catch (CertificateImportException e) {
					failure = e.getReason();
					m_state = previousState;
					m_snapshot = previousSnapshot;
				} catch (StoreException e) {
					failure = CertificateImportException.Reason.STORE_ERROR;
					m_state = previousState;
					m_snapshot = previousSnapshot;
				} catch (GeneralSecurityException | RuntimeException e) {
					failure = CertificateImportException.Reason.STORE_ERROR;
					m_state = previousState;
					m_snapshot = previousSnapshot;
				} finally {
					Arrays.fill(data, (byte) 0);
					Arrays.fill(pass, '\0');
					if (pkcs12 != null) Arrays.fill(pkcs12, (byte) 0);
					if (password != null) Arrays.fill(password, '\0');
				}
			}

			if (changed) notifyListeners();

			CertificateImportException.Reason result = failure;
			if (result == null) {
				post(() -> callback.onSuccess());
			} else {
				post(() -> callback.onFailure(result));
			}
		};

		Executor executor = getExecutor();
		if (executor == null) {
			task.run();
		} else {
			executor.execute(task);
		}
	}

	public void remove(RemoveCallback callback) {
		Runnable task = () -> {
			boolean keyDeleted = true;
			StoreException.Reason failure = null;
			boolean changed = false;

			synchronized (m_lock) {
				if (ensureLoadedLocked()) changed = true;

				if (m_store == null) {
					m_snapshot = null;
					m_state = State.NONE;
					m_lastError = null;
					changed = true;
				} else if (m_store.hasBlob() && !m_store.clearFile()) {
					failure = StoreException.Reason.IO;
				} else {
					keyDeleted = m_store.clearKey();
					m_snapshot = null;
					m_state = State.NONE;
					m_lastError = null;
					m_generation++;
					changed = true;
				}
			}

			if (changed) notifyListeners();

			boolean deleted = keyDeleted;
			if (failure == null) {
				post(() -> callback.onSuccess(deleted));
			} else {
				StoreException.Reason result = failure;
				post(() -> callback.onFailure(result));
			}
		};

		Executor executor = getExecutor();
		if (executor == null) {
			task.run();
		} else {
			executor.execute(task);
		}
	}

	public void addListener(Listener listener) {
		if (listener == null) return;
		m_listeners.add(listener);

		State state = getState();
		post(() -> listener.onStateChanged(state));
	}

	public void removeListener(Listener listener) {
		m_listeners.remove(listener);
	}

	private boolean ensureLoadedLocked() {
		if (m_state != State.LOADING) return false;

		if (m_store == null || m_sslContextFactory == null) {
			m_state = State.ERROR;
			m_lastError = StoreException.Reason.IO;
			return true;
		}

		try {
			ClientCertificate certificate = m_store.load();

			if (certificate == null) {
				m_state = State.NONE;
				m_lastError = null;
				return true;
			}

			SSLContext sslContext = m_sslContextFactory.create(certificate);
			m_snapshot = new Snapshot(++m_generation, certificate, sslContext);
			m_state = State.READY;
			m_lastError = null;
			return true;
		} catch (StoreException e) {
			m_state = State.ERROR;
			m_lastError = e.getReason();
			return true;
		} catch (GeneralSecurityException | RuntimeException e) {
			m_state = State.ERROR;
			m_lastError = StoreException.Reason.IO;
			return true;
		}
	}

	private Executor getExecutor() {
		synchronized (m_lock) {
			return m_executor;
		}
	}

	private void notifyListeners() {
		State state = getState();

		for (Listener listener : m_listeners) {
			post(() -> listener.onStateChanged(state));
		}
	}

	private void post(Runnable action) {
		Executor executor;

		synchronized (m_lock) {
			executor = m_callbackExecutor;
		}

		if (executor == null) {
			action.run();
		} else {
			executor.execute(action);
		}
	}
}
