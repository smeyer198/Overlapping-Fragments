package de.upb.cs;

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
import de.upb.cs.config.ConnectionConfig;
import de.upb.cs.config.Message;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.OverlappingField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OverlappingFragmentAnalysis {

    private static final Logger LOGGER = LoggerFactory.getLogger(OverlappingFragmentAnalysis.class);
    private final ConnectionConfig connectionConfig;
    private final OverlappingAnalysisConfig analysisConfig;

    public OverlappingFragmentAnalysis(ConnectionConfig connectionConfig, OverlappingAnalysisConfig analysisConfig) {
        this.connectionConfig = connectionConfig;
        this.analysisConfig = analysisConfig;
        initializeDtlsFields();
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

    private void initializeDtlsFields() {
        // Client connection
        analysisConfig.getTlsAttackerConfig().getDefaultClientConnection().setHostname(connectionConfig.getClientHostname());
        analysisConfig.getTlsAttackerConfig().getDefaultClientConnection().setPort(connectionConfig.getClientPort());
        analysisConfig.getTlsAttackerConfig().getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.UDP);
        analysisConfig.getTlsAttackerConfig().getDefaultClientConnection().setTimeout(connectionConfig.getClientTimeout());

        // Server connection
        analysisConfig.getTlsAttackerConfig().getDefaultServerConnection().setHostname(connectionConfig.getServerHostname());
        analysisConfig.getTlsAttackerConfig().getDefaultServerConnection().setPort(connectionConfig.getServerPort());
        analysisConfig.getTlsAttackerConfig().getDefaultServerConnection().setTransportHandlerType(TransportHandlerType.UDP);
        analysisConfig.getTlsAttackerConfig().getDefaultServerConnection().setTimeout(connectionConfig.getServerTimeout());

        // Set DTLS
        analysisConfig.getTlsAttackerConfig().setDefaultLayerConfiguration(LayerConfiguration.DTLS);
        analysisConfig.getTlsAttackerConfig().setWorkflowExecutorType(WorkflowExecutorType.DTLS);

        analysisConfig.getTlsAttackerConfig().setFinishWithCloseNotify(true);
        analysisConfig.getTlsAttackerConfig().setIgnoreRetransmittedCssInDtls(true);
        analysisConfig.getTlsAttackerConfig().setAddRetransmissionsToWorkflowTraceInDtls(false);
        analysisConfig.getTlsAttackerConfig().setMaxDtlsRetransmissions(0);

        // If we receive an alert, abort the handshake
        analysisConfig.getTlsAttackerConfig().setStopActionsAfterFatal(true);
        // config.setStopTraceAfterUnexpected(true);
        analysisConfig.getTlsAttackerConfig().setStopReceivingAfterFatal(true);
    }

    private AbstractAnalysis getAnalysis2() throws OverlappingFragmentException {
        OverlappingField field = analysisConfig.getOverlappingField();

        switch (field) {
            case NO_FIELD:
            case CLIENT_HELLO:
            case CLIENT_HELLO_VERSION:
            case CLIENT_HELLO_CIPHER_SUITE:
            case CLIENT_HELLO_EXTENSION:
                analysisConfig.setMessageType(HandshakeMessageType.CLIENT_HELLO);
                return new ClientHelloAnalysis(analysisConfig);
            case CLIENT_KEY_EXCHANGE:
            case CLIENT_KEY_EXCHANGE_RSA:
            case CLIENT_KEY_EXCHANGE_DH:
            case CLIENT_KEY_EXCHANGE_ECDH:
                analysisConfig.setMessageType(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
                return new ClientKeyExchangeAnalysis(analysisConfig);
            case SERVER_HELLO:
            case SERVER_HELLO_VERSION:
            case SERVER_HELLO_CIPHER_SUITE:
                analysisConfig.setMessageType(HandshakeMessageType.SERVER_HELLO);
                return new ServerHelloAnalysis(analysisConfig);
            case SERVER_KEY_EXCHANGE:
            case SERVER_KEY_EXCHANGE_DH:
            case SERVER_KEY_EXCHANGE_ECDH:
                analysisConfig.setMessageType(HandshakeMessageType.SERVER_KEY_EXCHANGE);
                return new ServerKeyExchangeAnalysis(analysisConfig);
            default:
                throw new OverlappingFragmentException("Cannot create analysis for field " + field);
        }
    }

    private AbstractAnalysis getAnalysis() throws OverlappingFragmentException {
        Message message = analysisConfig.getMessage();

        switch (message) {
            case NONE:
            case INITIAL_CLIENT_HELLO:
            case CLIENT_HELLO:
                analysisConfig.setMessageType(HandshakeMessageType.CLIENT_HELLO);
                return new ClientHelloAnalysis(analysisConfig);
            case RSA_CLIENT_KEY_EXCHANGE:
            case DH_CLIENT_KEY_EXCHANGE:
            case ECDH_CLIENT_KEY_EXCHANGE:
                analysisConfig.setMessageType(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
                return new ClientKeyExchangeAnalysis(analysisConfig);
            case SERVER_HELLO:
                analysisConfig.setMessageType(HandshakeMessageType.SERVER_HELLO);
                return new ServerHelloAnalysis(analysisConfig);
            case DH_SERVER_KEY_EXCHANGE:
            case ECDH_SERVER_KEY_EXCHANGE:
                analysisConfig.setMessageType(HandshakeMessageType.SERVER_KEY_EXCHANGE);
                return new ServerKeyExchangeAnalysis(analysisConfig);
            default:
                throw new OverlappingFragmentException("Cannot create analysis for message " + message);
        }
    }
}
