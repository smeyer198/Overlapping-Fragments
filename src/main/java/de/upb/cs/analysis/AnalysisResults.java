package de.upb.cs.analysis;

import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;

public class AnalysisResults {

    private byte[] finishedMac;
    private byte[] originalFinishedMac;
    private byte[] manipulatedFinishedMac;
    private boolean receivedFinishedMessage;
    private boolean handshakeExecutedAsPlanned;
    private TlsAction firstFailedMessageAction;

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
}
