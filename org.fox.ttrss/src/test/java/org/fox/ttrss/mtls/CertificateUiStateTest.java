package org.fox.ttrss.mtls;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.fox.ttrss.R;
import org.junit.Test;

public class CertificateUiStateTest {
	@Test
	public void loadingDisablesActions() {
		assertFalse(CertificateUiState.canImport(ClientCertificateManager.State.LOADING));
		assertFalse(CertificateUiState.showRemove(ClientCertificateManager.State.LOADING, true));
		assertEquals(R.string.client_certificate_summary_loading,
				CertificateUiState.summaryRes(ClientCertificateManager.State.LOADING));
	}

	@Test
	public void noneShowsNotImportedAndAllowsImport() {
		assertTrue(CertificateUiState.canImport(ClientCertificateManager.State.NONE));
		assertFalse(CertificateUiState.showRemove(ClientCertificateManager.State.NONE, false));
		assertEquals(R.string.client_certificate_summary_none,
				CertificateUiState.summaryRes(ClientCertificateManager.State.NONE));
	}

	@Test
	public void errorShowsUnreadableAndAllowsRemove() {
		assertTrue(CertificateUiState.canImport(ClientCertificateManager.State.ERROR));
		assertTrue(CertificateUiState.showRemove(ClientCertificateManager.State.ERROR, true));
		assertEquals(R.string.client_certificate_summary_error,
				CertificateUiState.summaryRes(ClientCertificateManager.State.ERROR));
	}

	@Test
	public void readyHasNoFixedSummary() {
		assertTrue(CertificateUiState.canImport(ClientCertificateManager.State.READY));
		assertEquals(0, CertificateUiState.summaryRes(ClientCertificateManager.State.READY));
	}
}
