package de.upb.cs.analysis;

import de.rub.nds.tlsattacker.core.constants.AlertDescription;
import de.rub.nds.tlsattacker.core.constants.HandshakeByteLength;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.crypto.MessageDigestCollector;
import de.rub.nds.tlsattacker.core.crypto.PseudoRandomFunction;
import de.rub.nds.tlsattacker.core.exceptions.CryptoException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.AlertMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.upb.cs.config.AnalysisConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class ResultsHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(ResultsHandler.class);
    private final AnalysisConfig analysisConfig;
    private final TlsContext context;
    private final WorkflowTrace trace;
    private final DigestHandler digestHandler;

    public ResultsHandler(AnalysisConfig analysisConfig, TlsContext context, WorkflowTrace trace, DigestHandler digestHandler) {
        this.analysisConfig = analysisConfig;
        this.context = context;
        this.trace = trace;
        this.digestHandler = digestHandler;
    }

    public void inspectWorkflowTrace() {
        StringBuilder sb = new StringBuilder("Executed actions:");
        TlsAction firstFailedAction = WorkflowTraceUtil.getFirstFailedAction(trace);

        for (TlsAction action : trace.getTlsActions()) {
            if (action.executedAsPlanned()) {
                sb.append("\n");
                sb.append(action);
            }
        }

        if (firstFailedAction != null) {
            sb.append("\n");
            sb.append(firstFailedAction);
        }
        LOGGER.info(sb.toString());
    }

    public void inspectHandshakeParameters() {
        String hp = "Handshake parameters:" + "\n\t" +
                "Proposed DTLS version: " + context.getChooser().getHighestProtocolVersion() +
                "\n\tSelected DTLS version: " + context.getSelectedProtocolVersion() +
                "\n\tProposed Cipher Suite: " + context.getChooser().getClientSupportedCipherSuites() +
                "\n\tSelected Cipher Suite: " + context.getSelectedCipherSuite() +
                "\n\tProposed SignatureAndHashAlgorithms: " + context.getChooser().getClientSupportedSignatureAndHashAlgorithms() +
                "\n\tSelected SignatureAndHashAlgorithm: " + context.getSelectedSignatureAndHashAlgorithm() +
                "\n";
        LOGGER.info(hp);
    }

    public void verifyClientFinishedMessage() {
        MessageDigestCollector originalTraceDigest = digestHandler.parseWorkflowTraceForClientFinished(trace, context, analysisConfig.getHandshakeMessageType(), false);
        MessageDigestCollector manipulatedTraceDigest = digestHandler.parseWorkflowTraceForClientFinished(trace, context, analysisConfig.getHandshakeMessageType(), true);

        try {
            FinishedMessage finishedMessage = trace.getLastReceivedMessage(FinishedMessage.class);
            byte[] verifyDataOriginalTrace = computeVerifyData(originalTraceDigest, PseudoRandomFunction.CLIENT_FINISHED_LABEL);
            byte[] verifyDataManipulatedTrace = computeVerifyData(manipulatedTraceDigest, PseudoRandomFunction.CLIENT_FINISHED_LABEL);

            if (finishedMessage != null) {
                byte[] finishedVerifyData = finishedMessage.getVerifyData().getValue();
                LOGGER.info("VerifyData:\n" +
                                "\tFinished:    {}\n" +
                                "\tOriginal:    {}\n" +
                                "\tManipulated: {}\n",
                        Utils.bytesToHexString(finishedVerifyData),
                        Utils.bytesToHexString(verifyDataOriginalTrace),
                        Utils.bytesToHexString(verifyDataManipulatedTrace));

                if (Arrays.equals(finishedVerifyData, verifyDataOriginalTrace)) {
                    LOGGER.info("Client interpreted original bytes");
                } else if (Arrays.equals(finishedVerifyData, verifyDataManipulatedTrace)) {
                    LOGGER.info("Client interpreted manipulated bytes");
                } else {
                    LOGGER.error("No Verify Data match");
                }
            } else {
                // In this case, the handshake failed because either the client aborted the handshake
                // or TLS-Attacker was not able to deal with the Finished message (e.g. it used the wrong
                // encryption algorithm)
                LOGGER.info("Did not receive ClientFinished message or unable to decrypt ClientFinished message");
            }
        } catch (CryptoException e) {
            LOGGER.error("Error while computing the verify data bytes");
        }
    }

    public void verifyServerFinishedMessage() {
        FinishedMessage finishedMessage = trace.getLastReceivedMessage(FinishedMessage.class);

        MessageDigestCollector originalTraceDigest = digestHandler.parseWorkflowTraceForServerFinished(trace, context, analysisConfig.getHandshakeMessageType(), false);
        MessageDigestCollector manipulatedTraceDigest = digestHandler.parseWorkflowTraceForServerFinished(trace, context, analysisConfig.getHandshakeMessageType(), true);

        try {
            byte[] verifyDataOriginalTrace = computeVerifyData(originalTraceDigest, PseudoRandomFunction.SERVER_FINISHED_LABEL);
            byte[] verifyDataManipulatedTrace = computeVerifyData(manipulatedTraceDigest, PseudoRandomFunction.SERVER_FINISHED_LABEL);

            if (finishedMessage != null) {
                byte[] finishedVerifyData = finishedMessage.getVerifyData().getValue();
                LOGGER.info("VerifyData:\n" +
                                "\tFinished:    {}\n" +
                                "\tOriginal:    {}\n" +
                                "\tManipulated: {}\n",
                        Utils.bytesToHexString(finishedVerifyData),
                        Utils.bytesToHexString(verifyDataOriginalTrace),
                        Utils.bytesToHexString(verifyDataManipulatedTrace));

                if (Arrays.equals(finishedVerifyData, verifyDataOriginalTrace)) {
                    if (!analysisConfig.isOverlappingBytesInDigest()) {
                        LOGGER.info("ClientFinished contained original bytes, Server interpreted original bytes");
                    } else {
                        LOGGER.info("MISMATCH 1");
                    }
                } else if (Arrays.equals(finishedVerifyData, verifyDataManipulatedTrace)) {
                    if (analysisConfig.isOverlappingBytesInDigest()) {
                        LOGGER.info("ClientFinished contained manipulated bytes, Server interpreted manipulated bytes");
                    } else {
                        LOGGER.info("MISMATCH 2");
                    }
                }
            } else {
                if (isDecryptError()) {
                    if (analysisConfig.isOverlappingBytesInDigest()) {
                        LOGGER.info("Server interpreted original bytes, ClientFinished contained manipulated bytes");
                    } else {
                        LOGGER.info("Server interpreted manipulated bytes, ClientFinished contained original bytes");
                    }
                }
            }
        } catch (CryptoException e) {
            LOGGER.error("Error while computing the verify data bytes");
        }
    }

    private byte[] computeVerifyData(MessageDigestCollector digest, String finishedLabel) throws CryptoException {
        // Follow https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/protocol/preparator/FinishedPreparator.java
        PRFAlgorithm prfAlgorithm = context.getChooser().getPRFAlgorithm();
        byte[] masterSecret = context.getChooser().getMasterSecret();
        byte[] handshakeMessageHash = digest.digest(context.getChooser().getSelectedProtocolVersion(), context.getChooser().getSelectedCipherSuite());

        return PseudoRandomFunction.compute(prfAlgorithm, masterSecret, finishedLabel, handshakeMessageHash, HandshakeByteLength.VERIFY_DATA);
    }

    private boolean isDecryptError() {
        MessageAction failingAction = (MessageAction) WorkflowTraceUtil.getFirstFailedAction(trace);

        if (failingAction == null) {
            return false;
        }

        for (ProtocolMessage<?> message : failingAction.getMessages()) {
            if (!(message instanceof AlertMessage)) {
                continue;
            }

            AlertMessage alertMessage = (AlertMessage) message;
            if (alertMessage.getDescription().getValue() == AlertDescription.DECRYPT_ERROR.getValue()) {
                return true;
            }
        }
        return false;
    }

}
