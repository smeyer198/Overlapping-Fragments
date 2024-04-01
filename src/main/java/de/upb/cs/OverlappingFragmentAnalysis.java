package de.upb.cs;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
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
import de.upb.cs.config.Field;
import de.upb.cs.config.FragmentConfig;
import de.upb.cs.config.LengthConfig;
import de.upb.cs.config.MessageType;
import de.upb.cs.config.OffsetConfig;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.Arrays;

public class OverlappingFragmentAnalysis {

    private static final Logger LOGGER = LoggerFactory.getLogger(OverlappingFragmentAnalysis.class);
    private final AnalysisConfig analysisConfig;

    public OverlappingFragmentAnalysis(ConnectionConfig connectionConfig, AnalysisConfig analysisConfig) {
        this.analysisConfig = analysisConfig;
        initializeDtlsFields(analysisConfig, connectionConfig);
    }

    public static void main(String[] args) throws OverlappingFragmentException {
        ConnectionConfig connectionConfig = new ConnectionConfig();
        connectionConfig.setClientHostname("172.19.142.193");
        connectionConfig.setClientPort(8090);
        connectionConfig.setServerHostname("localhost");
        connectionConfig.setServerPort(8080);

        AnalysisConfig config = new AnalysisConfig();
        config.setOverlappingBytesInDigest(false);

        FragmentConfig fragmentConfig1 = new FragmentConfig();
        fragmentConfig1.setOffset(0);
        fragmentConfig1.setLengthConfig(new LengthConfig(3, Field.CIPHER_SUITE));
        //fragmentConfig1.setAppendBytes("2c");

        FragmentConfig fragmentConfig2 = new FragmentConfig();
        fragmentConfig2.setOffsetConfig(new OffsetConfig(3, Field.CIPHER_SUITE));

        config.setFragments(Arrays.asList(fragmentConfig1, fragmentConfig2));
        config.setMessageType(MessageType.CLIENT_HELLO);
        config.setClientHelloCipherSuites(Arrays.asList(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));

        OverlappingFragmentAnalysis analysis = new OverlappingFragmentAnalysis(connectionConfig, config);
        analysis.executeAnalysis();
    }

    public void executeAnalysis() throws OverlappingFragmentException {
        LOGGER.info("Setup analysis...");
        AbstractAnalysis analysis = getOverlappingFragmentAnalysis(analysisConfig);
        analysis.initializeWorkflowTrace();
        LOGGER.info("Analysis setup done");

        State state = analysis.getState();

        LOGGER.info("Starting analysis...");
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DTLS, state);
        workflowExecutor.executeWorkflow();
        LOGGER.info("Analysis finished");

        analysis.analyzeResults();
    }

    private static void initializeDtlsFields(AnalysisConfig analysisConfig, ConnectionConfig connectionConfig) {
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
        analysisConfig.getTlsAttackerConfig().setMaxDtlsRetransmissions(analysisConfig.getMaxDtlsRetransmissions());

        // If we receive an alert, abort the handshake
        analysisConfig.getTlsAttackerConfig().setStopActionsAfterFatal(true);
        // config.setStopTraceAfterUnexpected(true);
        analysisConfig.getTlsAttackerConfig().setStopReceivingAfterFatal(true);
    }

    public static AbstractAnalysis getOverlappingFragmentAnalysis(ConnectionConfig connectionConfig, String pathToAnalysisConfig) throws JAXBException, FileNotFoundException, OverlappingFragmentException {
        JAXBContext context = JAXBContext.newInstance(AnalysisConfig.class);
        FileReader reader = new FileReader(pathToAnalysisConfig);
        AnalysisConfig analysisConfig = (AnalysisConfig) context.createUnmarshaller().unmarshal(reader);

        return getOverlappingFragmentAnalysis(connectionConfig, analysisConfig);
    }

    public static AbstractAnalysis getOverlappingFragmentAnalysis(ConnectionConfig connectionConfig, AnalysisConfig analysisConfig) throws OverlappingFragmentException{
        initializeDtlsFields(analysisConfig, connectionConfig);
        return getOverlappingFragmentAnalysis(analysisConfig);
    }

    private static AbstractAnalysis getOverlappingFragmentAnalysis(AnalysisConfig config) throws OverlappingFragmentException {
        MessageType messageType = config.getMessageType();

        switch (messageType) {
            case NONE:
            case INITIAL_CLIENT_HELLO:
            case CLIENT_HELLO:
                config.setHandshakeMessageType(HandshakeMessageType.CLIENT_HELLO);
                return new ClientHelloAnalysis(config);
            case RSA_CLIENT_KEY_EXCHANGE:
            case DH_CLIENT_KEY_EXCHANGE:
            case ECDH_CLIENT_KEY_EXCHANGE:
                config.setHandshakeMessageType(HandshakeMessageType.CLIENT_KEY_EXCHANGE);
                return new ClientKeyExchangeAnalysis(config);
            case SERVER_HELLO:
                config.setHandshakeMessageType(HandshakeMessageType.SERVER_HELLO);
                return new ServerHelloAnalysis(config);
            case DH_SERVER_KEY_EXCHANGE:
            case ECDH_SERVER_KEY_EXCHANGE:
                config.setHandshakeMessageType(HandshakeMessageType.SERVER_KEY_EXCHANGE);
                return new ServerKeyExchangeAnalysis(config);
            default:
                throw new OverlappingFragmentException("Cannot create analysis for message " + messageType);
        }
    }
}
