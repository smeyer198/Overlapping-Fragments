package de.upb.cs.analysis;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;

public class AnalysisResults {

    private byte[] finishedMac;
    private byte[] originalFinishedMac;
    private byte[] manipulatedFinishedMac;
    private boolean receivedServerHelloMessage;
    private boolean receivedFinishedMessage;
    private boolean handshakeExecutedAsPlanned;
    private TlsAction firstFailedMessageAction;

    private ProtocolVersion selectedVersion;
    private CipherSuite selectedCipherSuite;
    private SignatureAndHashAlgorithm selectedSignatureAndHashAlgorithm;

    public AnalysisResults() {}

    public byte[] getFinishedMac() {
        return finishedMac;
    }

    public void setFinishedMac(byte[] finishedMac) {
        this.finishedMac = finishedMac;
    }

    public byte[] getOriginalFinishedMac() {
        return originalFinishedMac;
    }

    public void setOriginalFinishedMac(byte[] originalFinishedMac) {
        this.originalFinishedMac = originalFinishedMac;
    }

    public byte[] getManipulatedFinishedMac() {
        return manipulatedFinishedMac;
    }

    public void setManipulatedFinishedMac(byte[] manipulatedFinishedMac) {
        this.manipulatedFinishedMac = manipulatedFinishedMac;
    }

    public boolean isReceivedServerHelloMessage() {
        return receivedServerHelloMessage;
    }

    public void setReceivedServerHelloMessage(boolean receivedServerHelloMessage) {
        this.receivedServerHelloMessage = receivedServerHelloMessage;
    }

    public boolean receivedFinishedMessage() {
        return receivedFinishedMessage;
    }

    public void setReceivedFinishedMessage(boolean receivedFinishedMessage) {
        this.receivedFinishedMessage = receivedFinishedMessage;
    }

    public boolean isHandshakeExecutedAsPlanned() {
        return handshakeExecutedAsPlanned;
    }

    public void setHandshakeExecutedAsPlanned(boolean handshakeExecutedAsPlanned) {
        this.handshakeExecutedAsPlanned = handshakeExecutedAsPlanned;
    }

    public TlsAction getFirstFailedMessageAction() {
        return firstFailedMessageAction;
    }

    public void setFirstFailedMessageAction(TlsAction firstFailedMessageAction) {
        this.firstFailedMessageAction = firstFailedMessageAction;
    }

    public ProtocolVersion getSelectedVersion() {
        return selectedVersion;
    }

    public void setSelectedVersion(ProtocolVersion selectedVersion) {
        this.selectedVersion = selectedVersion;
    }

    public CipherSuite getSelectedCipherSuite() {
        return selectedCipherSuite;
    }

    public void setSelectedCipherSuite(CipherSuite selectedCipherSuite) {
        this.selectedCipherSuite = selectedCipherSuite;
    }

    public SignatureAndHashAlgorithm getSelectedSignatureAndHashAlgorithm() {
        return selectedSignatureAndHashAlgorithm;
    }

    public void setSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm selectedSignatureAndHashAlgorithm) {
        this.selectedSignatureAndHashAlgorithm = selectedSignatureAndHashAlgorithm;
    }
}
