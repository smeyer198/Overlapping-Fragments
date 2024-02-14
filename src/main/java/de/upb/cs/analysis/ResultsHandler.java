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
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.message.DigestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;

public class ResultsHandler {

    private static final Logger LOGGER = LogManager.getLogger();
    private final OverlappingAnalysisConfig analysisConfig;
    private final TlsContext context;
    private final WorkflowTrace trace;
    private final DigestHandler digestHandler;

    public ResultsHandler(OverlappingAnalysisConfig analysisConfig, TlsContext context, WorkflowTrace trace, DigestHandler digestHandler) {
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
                "Proposed DTLS version: " + context.getHighestClientProtocolVersion() +
                "\n\tSelected DTLS version: " + context.getSelectedProtocolVersion() +
                "\n\tProposed Cipher Suite: " + context.getClientSupportedCipherSuites() +
                "\n\tSelected Cipher Suite: " + context.getSelectedCipherSuite() +
                "\n\tProposed SignatureAndHashAlgorithms: " + context.getClientSupportedSignatureAndHashAlgorithms() +
                "\n\tSelected SignatureAndHashAlgorithm: " + context.getSelectedSignatureAndHashAlgorithm() +
                "\n";
        LOGGER.info(hp);
    }

    public void verifyClientFinishedMessage() {
        MessageDigestCollector originalTraceDigest = digestHandler.parseWorkflowTraceForClientFinished(trace, context, analysisConfig.getMessageType(), false);
        MessageDigestCollector manipulatedTraceDigest = digestHandler.parseWorkflowTraceForClientFinished(trace, context, analysisConfig.getMessageType(), true);

        try {
            FinishedMessage finishedMessage = trace.getLastReceivedMessage(FinishedMessage.class);
            byte[] verifyDataOriginalTrace = computeVerifyData(originalTraceDigest, PseudoRandomFunction.CLIENT_FINISHED_LABEL);
            byte[] verifyDataManipulatedTrace = computeVerifyData(manipulatedTraceDigest, PseudoRandomFunction.CLIENT_FINISHED_LABEL);

            if (finishedMessage != null) {
                byte[] finishedVerifyData = finishedMessage.getVerifyData().getValue();
                LOGGER.debug("VerifyData:\n" +
                                "\tFinished:    {}\n" +
                                "\tOriginal:    {}\n" +
                                "\tManipulated: {}\n",
                        finishedVerifyData, verifyDataOriginalTrace, verifyDataManipulatedTrace);

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
                LOGGER.info("Did not receive ClientFinished message. Client most likely interpreted manipulated bytes");
            }
        } catch (CryptoException e) {
            LOGGER.error("Error while computing the verify data bytes");
        }
    }

    public void verifyServerFinishedMessage() {
        FinishedMessage finishedMessage = trace.getLastReceivedMessage(FinishedMessage.class);

        MessageDigestCollector originalTraceDigest = digestHandler.parseWorkflowTraceForServerFinished(trace, context, analysisConfig.getMessageType(), false);
        MessageDigestCollector manipulatedTraceDigest = digestHandler.parseWorkflowTraceForServerFinished(trace, context, analysisConfig.getMessageType(), true);

        try {
            byte[] verifyDataOriginalTrace = computeVerifyData(originalTraceDigest, PseudoRandomFunction.SERVER_FINISHED_LABEL);
            byte[] verifyDataManipulatedTrace = computeVerifyData(manipulatedTraceDigest, PseudoRandomFunction.SERVER_FINISHED_LABEL);

            if (finishedMessage != null) {
                byte[] finishedVerifyData = finishedMessage.getVerifyData().getValue();
                LOGGER.debug("VerifyData:\n" +
                                "\tFinished:    {}\n" +
                                "\tOriginal:    {}\n" +
                                "\tManipulated: {}\n",
                        finishedVerifyData, verifyDataOriginalTrace, verifyDataManipulatedTrace);

                if (Arrays.equals(finishedVerifyData, verifyDataOriginalTrace)) {
                    if (!analysisConfig.isOverlappingBytesInDigest()) {
                        LOGGER.info("ClientFinished contained original bytes, Server interpreted original bytes");
                    } else {
                        LOGGER.info("WARNING 1");
                    }
                } else if (Arrays.equals(finishedVerifyData, verifyDataManipulatedTrace)) {
                    if (analysisConfig.isOverlappingBytesInDigest()) {
                        LOGGER.info("ClientFinished contained manipulated bytes, Server interpreted manipulated bytes");
                    } else {
                        LOGGER.info("WARNING 2");
                    }
                }
            } else {
                if (isDecryptError()) {
                    if (analysisConfig.isOverlappingBytesInDigest()) {
                        LOGGER.info("Server interpreted original bytes, but ClientFinished contained manipulated bytes");
                    } else {
                        LOGGER.info("Server interpreted manipulated bytes, but ClientFinished contained original bytes");
                    }
                }
            }
        } catch (CryptoException e) {
            LOGGER.error("Error while computing the verify data bytes");
        }
    }

    private void logFinishedResults(FinishedMessage finishedMessage, byte[] verifyDataOriginalTrace, byte[] verifyDataManipulatedTrace, String sendingPeer, String receivingPeer) {

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

    public void checkForExploit() {
        if (!trace.executedAsPlanned()) {
            MessageAction failingAction = (MessageAction) WorkflowTraceUtil.getFirstFailedAction(trace);

            LOGGER.info("Handshake not executed as planned. Received error message\n{}", failingAction.getMessages());
            return;
        }

        if (analysisConfig.isOverlappingBytesInDigest()) {
            LOGGER.info("Cannot find exploit if manipulated bytes are used in FinishedMessage");
            return;
        }

        switch (analysisConfig.getOverlappingField()) {
            case CLIENT_HELLO_VERSION:
                if (context.getHighestClientProtocolVersion() != context.getSelectedProtocolVersion()) {
                    LOGGER.info("Found exploit for ClientHello version");
                }
                break;
            case CLIENT_HELLO_CIPHER_SUITE:
                if (context.getClientSupportedCipherSuites().get(0) != context.getSelectedCipherSuite()) {
                    LOGGER.info("Found exploit for ClientHello cipher suites");
                }
                break;
            default:
                LOGGER.info("No exploit found");
        }
    }
}
