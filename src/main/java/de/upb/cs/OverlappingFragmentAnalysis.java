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
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.ConnectionConfig;
import de.upb.cs.config.FragmentConfig;
import de.upb.cs.config.MessageType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;

public class OverlappingFragmentAnalysis {

    private static final Logger LOGGER = LoggerFactory.getLogger(OverlappingFragmentAnalysis.class);
    private final ConnectionConfig connectionConfig;
    private final AnalysisConfig analysisConfig;

    public OverlappingFragmentAnalysis(ConnectionConfig connectionConfig, AnalysisConfig analysisConfig) {
        this.connectionConfig = connectionConfig;
        this.analysisConfig = analysisConfig;
        initializeDtlsFields();
    }


    public static void main(String[] args) throws OverlappingFragmentException {
        ConnectionConfig connectionConfig = new ConnectionConfig();
        connectionConfig.setClientHostname("172.19.142.193");
        connectionConfig.setClientPort(8090);
        connectionConfig.setServerHostname("localhost");
        connectionConfig.setServerPort(8080);

        AnalysisConfig config = new AnalysisConfig();
        config.setOverlappingBytesInDigest(true);

        FragmentConfig fragmentConfig = new FragmentConfig();
        fragmentConfig.setOffset(0);
        fragmentConfig.setLength(36);
        fragmentConfig.setAppendBytes("2F");

        FragmentConfig fragmentConfig1 = new FragmentConfig();
        fragmentConfig1.setOffset(36);

        config.setFragments(Arrays.asList(fragmentConfig, fragmentConfig1));
        config.setMessageType(MessageType.ECDH_SERVER_KEY_EXCHANGE);

        OverlappingFragmentAnalysis analysis = new OverlappingFragmentAnalysis(connectionConfig, config);
        analysis.executeAnalysis();
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

    private AbstractAnalysis getAnalysis() throws OverlappingFragmentException {
        MessageType messageType = analysisConfig.getMessageType();

        switch (messageType) {
            case NONE:
            case INITIAL_CLIENT_HELLO:
            case CLIENT_HELLO:
                analysisConfig.setHandshakeMessageType(HandshakeMessageType.CLIENT_HELLO);
                return new ClientHelloAnalysis(analysisConfig);
            case RSA_CLIENT_KEY_EXCHANGE:
            case DH_CLIENT_KEY_EXCHANGE:
            case ECDH_CLIENT_KEY_EXCHANGE:
                analysisConfig.setHandshakeMessageType(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
                return new ClientKeyExchangeAnalysis(analysisConfig);
            case SERVER_HELLO:
                analysisConfig.setHandshakeMessageType(HandshakeMessageType.SERVER_HELLO);
                return new ServerHelloAnalysis(analysisConfig);
            case DH_SERVER_KEY_EXCHANGE:
            case ECDH_SERVER_KEY_EXCHANGE:
                analysisConfig.setHandshakeMessageType(HandshakeMessageType.SERVER_KEY_EXCHANGE);
                return new ServerKeyExchangeAnalysis(analysisConfig);
            default:
                throw new OverlappingFragmentException("Cannot create analysis for message " + messageType);
        }
    }
}
