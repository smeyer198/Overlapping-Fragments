package de.upb.cs;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.layer.constant.LayerConfiguration;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.transport.TransportHandlerType;
import de.upb.cs.analysis.AbstractAnalysis;
import de.upb.cs.analysis.ClientHelloAnalysis;
import de.upb.cs.analysis.ClientKeyExchangeAnalysis;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.analysis.ServerHelloAnalysis;
import de.upb.cs.analysis.ServerKeyExchangeAnalysis;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.OverlappingField;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class OverlappingFragmentAnalysis {

    private static final Logger LOGGER = LogManager.getLogger();
    private final OverlappingAnalysisConfig analysisConfig;
    private final Config tlsAttackerConfig;

    public OverlappingFragmentAnalysis(OverlappingAnalysisConfig analysisConfig) {
        this.analysisConfig = analysisConfig;
        this.tlsAttackerConfig = this.createDtlsConfig();
        tlsAttackerConfig.setAutoSelectCertificate(false);
    }

    public void executeAnalysis() throws OverlappingFragmentException {
        LOGGER.info("Setup analysis...");
        AbstractAnalysis analysis = this.getAnalysis();
        analysis.initializeWorkflowTrace();
        LOGGER.info("Analysis setup done");

        State state = analysis.getState();

        LOGGER.info("Starting analysis...");
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DTLS, state);
        workflowExecutor.executeWorkflow();
        LOGGER.info("Analysis finished");

        analysis.analyzeResults();
    }

    public OverlappingAnalysisConfig getAnalysisConfig() {
        return analysisConfig;
    }

    public Config getTlsAttackerConfig() {
        return tlsAttackerConfig;
    }

    private Config createDtlsConfig() {
        Config config = new Config();

        // Client connection
        config.getDefaultClientConnection().setHostname(getAnalysisConfig().getConnectionConfig().getClientHostname());
        config.getDefaultClientConnection().setPort(getAnalysisConfig().getConnectionConfig().getClientPort());
        config.getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.UDP);
        config.getDefaultClientConnection().setTimeout(getAnalysisConfig().getConnectionConfig().getClientTimeout());

        // Server connection
        config.getDefaultServerConnection().setHostname(getAnalysisConfig().getConnectionConfig().getServerHostname());
        config.getDefaultServerConnection().setPort(getAnalysisConfig().getConnectionConfig().getServerPort());
        config.getDefaultServerConnection().setTransportHandlerType(TransportHandlerType.UDP);
        config.getDefaultServerConnection().setTimeout(getAnalysisConfig().getConnectionConfig().getServerTimeout());

        // Set DTLS (selectedVersion is used in the records)
        config.setDefaultSelectedProtocolVersion(analysisConfig.getRecordVersion());
        config.setDefaultLayerConfiguration(LayerConfiguration.DTLS);
        config.setWorkflowExecutorType(WorkflowExecutorType.DTLS);

        config.setFinishWithCloseNotify(true);
        config.setIgnoreRetransmittedCssInDtls(true);
        config.setAddRetransmissionsToWorkflowTraceInDtls(false);

        // If we receive an alert, abort the handshake
        config.setStopActionsAfterFatal(true);
        config.setStopTraceAfterUnexpected(true);
        config.setStopReceivingAfterFatal(true);

        return config;
    }

    private AbstractAnalysis getAnalysis() throws OverlappingFragmentException {
        OverlappingField field = getAnalysisConfig().getOverlappingField();

        switch (field) {
            case CLIENT_HELLO_EMPTY:
            case CLIENT_HELLO_VERSION:
            case CLIENT_HELLO_CIPHER_SUITE:
            case CLIENT_HELLO_EXTENSION:
                getAnalysisConfig().setMessageType(HandshakeMessageType.CLIENT_HELLO);
                return new ClientHelloAnalysis(getTlsAttackerConfig(), getAnalysisConfig());
            case CLIENT_KEY_EXCHANGE_RSA:
            case CLIENT_KEY_EXCHANGE_DH:
            case CLIENT_KEY_EXCHANGE_ECDH:
                getAnalysisConfig().setMessageType(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
                return new ClientKeyExchangeAnalysis(getTlsAttackerConfig(), getAnalysisConfig());
            case SERVER_HELLO_EMPTY:
            case SERVER_HELLO_VERSION:
            case SERVER_HELLO_CIPHER_SUITE:
                getAnalysisConfig().setMessageType(HandshakeMessageType.SERVER_HELLO);
                return new ServerHelloAnalysis(getTlsAttackerConfig(), getAnalysisConfig());
            case SERVER_KEY_EXCHANGE_DH:
            case SERVER_KEY_EXCHANGE_ECDH:
                getAnalysisConfig().setMessageType(HandshakeMessageType.SERVER_KEY_EXCHANGE);
                return new ServerKeyExchangeAnalysis(getTlsAttackerConfig(), getAnalysisConfig());
            default:
                throw new OverlappingFragmentException("Cannot create analysis for field " + field);
        }
    }
}
