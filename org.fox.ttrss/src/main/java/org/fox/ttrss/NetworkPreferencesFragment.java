package org.fox.ttrss;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Bundle;
import android.text.Editable;
import android.text.InputType;
import android.widget.EditText;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.preference.Preference;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.PreferenceManager;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import org.fox.ttrss.mtls.CertificateImportException;
import org.fox.ttrss.mtls.CertificateUiState;
import org.fox.ttrss.mtls.ClientCertificateManager;
import org.fox.ttrss.mtls.StoreException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.DateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import okhttp3.HttpUrl;

public class NetworkPreferencesFragment extends PreferenceFragmentCompat {
	private static final int MAX_CERTIFICATE_BYTES = 5 * 1024 * 1024;
	private static final String[] CERTIFICATE_MIME_TYPES = {
			"application/x-pkcs12",
			"application/pkcs12",
			"application/octet-stream",
			"*/*"
	};

	private final ActivityResultLauncher<String[]> m_certificatePicker =
			registerForActivityResult(new ActivityResultContracts.OpenDocument(),
					this::onCertificateSelected);

	private ClientCertificateManager m_manager;
	private ClientCertificateManager.Listener m_listener;

	@Override
	public void onCreatePreferences(@Nullable Bundle savedInstanceState, @Nullable String rootKey) {
		setPreferencesFromResource(R.xml.preferences_network, rootKey);

		m_manager = ClientCertificateManager.getInstance();
		m_listener = this::renderState;

		Preference importPreference = findPreference("client_certificate_import");
		if (importPreference != null) {
			importPreference.setOnPreferenceClickListener(preference -> {
				confirmReplaceOrPick();
				return true;
			});
		}

		Preference removePreference = findPreference("client_certificate_remove");
		if (removePreference != null) {
			removePreference.setOnPreferenceClickListener(preference -> {
				confirmRemove();
				return true;
			});
		}
	}

	@Override
	public void onStart() {
		super.onStart();

		if (m_manager != null) {
			m_manager.addListener(m_listener);
			renderState(m_manager.getState());
		}
	}

	@Override
	public void onStop() {
		if (m_manager != null) m_manager.removeListener(m_listener);

		super.onStop();
	}

	private void confirmReplaceOrPick() {
		if (m_manager.hasBlob()) {
			new MaterialAlertDialogBuilder(requireContext())
					.setMessage(R.string.client_certificate_replace_confirm)
					.setPositiveButton(R.string.dialog_ok, (dialog, which) -> launchPicker())
					.setNegativeButton(R.string.dialog_cancel, null)
					.show();
		} else {
			launchPicker();
		}
	}

	private void launchPicker() {
		m_certificatePicker.launch(CERTIFICATE_MIME_TYPES);
	}

	private void onCertificateSelected(Uri uri) {
		if (uri == null) return;

		showHttpWarning();

		Context appContext = requireContext().getApplicationContext();
		String displayName = uri.getLastPathSegment();
		if (displayName == null || displayName.isEmpty()) displayName = "client-certificate.p12";
		String finalDisplayName = displayName;

		ExecutorService executor = Executors.newSingleThreadExecutor();
		executor.execute(() -> {
			ReadResult result = readBounded(appContext, uri, MAX_CERTIFICATE_BYTES);

			ContextCompat.getMainExecutor(appContext).execute(() -> {
				executor.shutdown();

				if (!isAdded()) {
					if (result.data != null) Arrays.fill(result.data, (byte) 0);
					return;
				}

				if (result.data == null) {
					toast(result.tooLarge
							? R.string.client_certificate_error_too_large
							: R.string.client_certificate_error_unreadable);
					return;
				}

				showPasswordDialog(result.data, finalDisplayName);
			});
		});
	}

	private static final class ReadResult {
		final byte[] data;
		final boolean tooLarge;

		ReadResult(byte[] data, boolean tooLarge) {
			this.data = data;
			this.tooLarge = tooLarge;
		}
	}

	private ReadResult readBounded(Context context, Uri uri, int maxBytes) {
		try (InputStream in = context.getContentResolver().openInputStream(uri)) {
			if (in == null) return new ReadResult(null, false);

			ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] buffer = new byte[8192];
			int total = 0;
			int read;

			while ((read = in.read(buffer)) != -1) {
				total += read;

				if (total > maxBytes) return new ReadResult(null, true);

				out.write(buffer, 0, read);
			}

			return new ReadResult(out.toByteArray(), false);
		} catch (IOException e) {
			return new ReadResult(null, false);
		}
	}

	private void showPasswordDialog(byte[] data, String displayName) {
		EditText input = new EditText(requireContext());
		input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
		input.setHint(R.string.client_certificate_password_hint);

		new MaterialAlertDialogBuilder(requireContext())
				.setTitle(R.string.client_certificate_password_title)
				.setView(input)
				.setCancelable(false)
				.setPositiveButton(R.string.dialog_ok, (dialog, which) -> {
					Editable editable = input.getText();
					char[] password = new char[editable.length()];
					editable.getChars(0, editable.length(), password, 0);
					editable.clear();
					startImport(data, password, displayName);
				})
				.setNegativeButton(R.string.dialog_cancel,
						(dialog, which) -> Arrays.fill(data, (byte) 0))
				.show();
	}

	private void startImport(byte[] data, char[] password, String displayName) {
		m_manager.importCertificate(data, password, displayName,
				new ClientCertificateManager.ImportCallback() {
					@Override
					public void onSuccess() {
						Arrays.fill(password, '\0');
						Arrays.fill(data, (byte) 0);

						if (!isAdded()) return;

						toast(R.string.client_certificate_imported);
						renderState(m_manager.getState());
					}

					@Override
					public void onFailure(CertificateImportException.Reason reason) {
						Arrays.fill(password, '\0');
						Arrays.fill(data, (byte) 0);

						if (isAdded()) toast(reasonRes(reason));
					}
				});
	}

	private void confirmRemove() {
		new MaterialAlertDialogBuilder(requireContext())
				.setMessage(R.string.client_certificate_remove_confirm)
				.setPositiveButton(R.string.dialog_ok, (dialog, which) ->
						m_manager.remove(new ClientCertificateManager.RemoveCallback() {
							@Override
							public void onSuccess(boolean keyDeleted) {
								if (!isAdded()) return;

								toast(R.string.client_certificate_removed);
								if (!keyDeleted) {
									toast(R.string.client_certificate_remove_cleanup_failed);
								}
								renderState(m_manager.getState());
							}

							@Override
							public void onFailure(StoreException.Reason reason) {
								if (isAdded()) toast(R.string.client_certificate_remove_failed);
							}
						}))
				.setNegativeButton(R.string.dialog_cancel, null)
				.show();
	}

	private void renderState(ClientCertificateManager.State state) {
		Preference importPreference = findPreference("client_certificate_import");
		Preference removePreference = findPreference("client_certificate_remove");

		if (importPreference == null || removePreference == null) return;

		boolean hasBlob = m_manager.hasBlob();

		importPreference.setEnabled(CertificateUiState.canImport(state));
		importPreference.setTitle(hasBlob
				? R.string.client_certificate_replace
				: R.string.client_certificate_import);

		int summaryRes = CertificateUiState.summaryRes(state);

		if (summaryRes != 0) {
			importPreference.setSummary(summaryRes);
		} else {
			ClientCertificateManager.Snapshot snapshot = m_manager.getSnapshot();

			if (snapshot != null) {
				String date = DateFormat.getDateInstance().format(
						new Date(snapshot.getCertificate().getNotAfterEpochMillis()));
				importPreference.setSummary(getString(
						R.string.client_certificate_summary_ready,
						snapshot.getCertificate().getSubject(), date));
			} else {
				importPreference.setSummary(R.string.client_certificate_summary_error);
			}
		}

		removePreference.setVisible(CertificateUiState.showRemove(state, hasBlob));
		removePreference.setEnabled(state != ClientCertificateManager.State.LOADING);
	}

	private int reasonRes(CertificateImportException.Reason reason) {
		switch (reason) {
			case WRONG_PASSWORD:
				return R.string.client_certificate_error_wrong_password;
			case MISSING_KEY:
				return R.string.client_certificate_error_missing_key;
			case MISSING_CHAIN:
				return R.string.client_certificate_error_missing_chain;
			case UNSUPPORTED_KEY:
				return R.string.client_certificate_error_unsupported_key;
			case EXPIRED:
			case NOT_YET_VALID:
				return R.string.client_certificate_error_expired;
			case STORE_ERROR:
				return R.string.client_certificate_error_store;
			case UNREADABLE:
			default:
				return R.string.client_certificate_error_unreadable;
		}
	}

	private void showHttpWarning() {
		SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(requireContext());
		String url = prefs.getString("ttrss_url", "").trim();
		HttpUrl parsed = HttpUrl.parse(url);

		if (parsed == null || !parsed.isHttps()) {
			toast(R.string.client_certificate_http_warning);
		}
	}

	private void toast(int messageRes) {
		if (!isAdded()) return;
		Toast.makeText(requireContext(), messageRes, Toast.LENGTH_LONG).show();
	}
}
