package de.upb.cs;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
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
import java.util.List;

public class OverlappingFragmentAnalysis {

    private static final Logger LOGGER = LoggerFactory.getLogger(OverlappingFragmentAnalysis.class);
    private final AnalysisConfig analysisConfig;

    public OverlappingFragmentAnalysis(String hostname, int port, int timeout, AnalysisConfig analysisConfig) {
        this.analysisConfig = analysisConfig;
        initializeDtlsFields(analysisConfig, hostname, port, timeout);
    }

    public static void main(String[] args) throws OverlappingFragmentException, JAXBException, FileNotFoundException {
        String hostname = "172.19.142.193";
        int port = 8090;
        int timeout = 2000;

        AnalysisConfig config = new AnalysisConfig();
        config.setMessageType(MessageType.CLIENT_HELLO);
        config.setClientHelloCipherSuites(List.of(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA));
        config.setClientHelloSignatureAndHashAlgorithms(Arrays.asList(SignatureAndHashAlgorithm.RSA_SHA256, SignatureAndHashAlgorithm.ECDSA_SHA256));

        FragmentConfig fragment1 = new FragmentConfig();
        fragment1.setOffset(0);
        fragment1.setLengthConfig(new LengthConfig(2, Field.EXTENSION));

        FragmentConfig fragment2 = new FragmentConfig();
        fragment2.setOffsetConfig(new OffsetConfig(2, Field.EXTENSION));
        fragment2.setPrependBytes("03");

        config.setFragments(Arrays.asList(fragment1, fragment2));

        OverlappingFragmentAnalysis analysis = new OverlappingFragmentAnalysis(hostname, port, timeout, config);
        analysis.executeAnalysis();
    }

    public void executeAnalysis() throws OverlappingFragmentException, JAXBException, FileNotFoundException {
        LOGGER.info("Setup analysis...");
        //AbstractAnalysis analysis = getOverlappingFragmentAnalysis(analysisConfig);
        AbstractAnalysis analysis = getOverlappingFragmentAnalysis("127.0.0.1", 8090, "C:\\Users\\Sven\\Documents\\GitHub\\OverlappingFragments\\consecutiveTypeAOriginalOrder.xml");
        analysis.initializeWorkflowTrace();
        LOGGER.info("Analysis setup done");

        State state = analysis.getState();

        LOGGER.info("Starting analysis...");
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DTLS, state);
        workflowExecutor.executeWorkflow();
        LOGGER.info("Analysis finished");

        analysis.analyzeResults();
    }

    private static void initializeDtlsFields(AnalysisConfig analysisConfig, String hostname, int port, int timeout) {
        // Client connection
        analysisConfig.getTlsAttackerConfig().getDefaultClientConnection().setHostname(hostname);
        analysisConfig.getTlsAttackerConfig().getDefaultClientConnection().setPort(port);
        analysisConfig.getTlsAttackerConfig().getDefaultClientConnection().setTransportHandlerType(TransportHandlerType.UDP);
        analysisConfig.getTlsAttackerConfig().getDefaultClientConnection().setTimeout(timeout);

        // Server connection
        analysisConfig.getTlsAttackerConfig().getDefaultServerConnection().setHostname(hostname);
        analysisConfig.getTlsAttackerConfig().getDefaultServerConnection().setPort(port);
        analysisConfig.getTlsAttackerConfig().getDefaultServerConnection().setTransportHandlerType(TransportHandlerType.UDP);
        analysisConfig.getTlsAttackerConfig().getDefaultServerConnection().setTimeout(timeout);

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

    public static AbstractAnalysis getOverlappingFragmentAnalysis(String hostname, int port, String pathToAnalysisConfig) throws JAXBException, FileNotFoundException, OverlappingFragmentException {
        return getOverlappingFragmentAnalysis(hostname, port, 2000, pathToAnalysisConfig);
    }

    /**
     * Initialize the analysis based on connection information.
     *
     * @param hostname the host to connect to
     * @param port the port of the host
     * @param timeout timeout when waiting for messages
     * @param pathToAnalysisConfig path to an XML document describing the AnalysisConfig
     * @return the analysis instance with the initialized Config and WorkflowTrace
     * @throws OverlappingFragmentException if there is a problem when creating the fragments
     */
    public static AbstractAnalysis getOverlappingFragmentAnalysis(String hostname, int port, int timeout, String pathToAnalysisConfig) throws JAXBException, FileNotFoundException, OverlappingFragmentException {
        JAXBContext context = JAXBContext.newInstance(AnalysisConfig.class);
        FileReader reader = new FileReader(pathToAnalysisConfig);
        AnalysisConfig analysisConfig = (AnalysisConfig) context.createUnmarshaller().unmarshal(reader);

        return getOverlappingFragmentAnalysis(hostname, port, timeout, analysisConfig);
    }

    /**
     * Initialize the analysis based on connection information.
     *
     * @param hostname the host to connect to
     * @param port the port of the host
     * @param timeout timeout when waiting for messages
     * @param analysisConfig AnalysisConfig containing all required information
     * @return the analysis instance with the initialized Config and WorkflowTrace
     * @throws OverlappingFragmentException if there is a problem when creating the fragments
     */
    public static AbstractAnalysis getOverlappingFragmentAnalysis(String hostname, int port, int timeout, AnalysisConfig analysisConfig) throws OverlappingFragmentException{
        initializeDtlsFields(analysisConfig, hostname, port, timeout);
        return getOverlappingFragmentAnalysis(analysisConfig);
    }

    /**
     * Initialize the analysis based on connection information. This should only be called
     * after the AnalysisConfig has been instantiated and a Config with setTlsAttackerConfig
     * has been set (used only for TLS-Scanner).
     *
     * @return the analysis instance with the initialized Config and WorkflowTrace
     * @throws OverlappingFragmentException if there is a problem when creating the fragments
     */
    public static AbstractAnalysis getOverlappingFragmentAnalysis(AnalysisConfig config) throws OverlappingFragmentException {
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
