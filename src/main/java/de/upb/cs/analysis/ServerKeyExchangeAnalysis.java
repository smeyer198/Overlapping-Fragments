package de.upb.cs.analysis;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.upb.cs.action.ReceiveDynamicClientKeyExchangeAction;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.message.ServerKeyExchangeBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class ServerKeyExchangeAnalysis extends AbstractAnalysis {

    private static final Logger LOGGER = LoggerFactory.getLogger(ServerKeyExchangeAnalysis.class);
    private final SendDynamicServerKeyExchangeAction dynamicServerKeyExchangeAction;

    public ServerKeyExchangeAnalysis(AnalysisConfig analysisConfig) throws OverlappingFragmentException {
        super(analysisConfig, "server");

        this.dynamicServerKeyExchangeAction = new SendDynamicServerKeyExchangeAction(getAliasContext());
    }

    @Override
    public void initializeWorkflowTrace() {
        if (isCookieExchange()) {
            getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new ClientHelloMessage()));
            getTrace().addTlsAction(new SendAction(getAliasContext(), new HelloVerifyRequestMessage()));
        }

        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new ClientHelloMessage()));
        getTrace().addTlsAction(new SendAction(getAliasContext(), new ServerHelloMessage(getConfig())));
        getTrace().addTlsAction(new SendAction(getAliasContext(), new CertificateMessage()));
        getTrace().addTlsAction(dynamicServerKeyExchangeAction);

        if (isClientAuthentication()) {
            getTrace().addTlsAction(new SendAction(getAliasContext(), new CertificateRequestMessage()));

        }
        getTrace().addTlsAction(new SendAction(getAliasContext(), new ServerHelloDoneMessage()));

        if (isClientAuthentication()) {
            getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new CertificateMessage()));

        }

        getTrace().addTlsAction(new ReceiveDynamicClientKeyExchangeAction(getAliasContext()));

        if (isClientAuthentication()) {
            getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new CertificateVerifyMessage()));
        }

        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new ChangeCipherSpecMessage()));
        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new FinishedMessage()));
        getTrace().addTlsAction(new SendAction(getAliasContext(), new ChangeCipherSpecMessage()));
        getTrace().addTlsAction(new SendAction(getAliasContext(), new FinishedMessage()));
    }

    @Override
    public List<DtlsHandshakeMessageFragment> fragmentMessage(HandshakeMessageType handshakeMessageType, DtlsHandshakeMessageFragment mergedFragment, List<DtlsHandshakeMessageFragment> originalFragments) {
        if (handshakeMessageType != HandshakeMessageType.SERVER_KEY_EXCHANGE) {
            return originalFragments;
        }

        List<ProtocolMessage> messages = dynamicServerKeyExchangeAction.getSendMessages();
        if (messages.isEmpty()) {
            return originalFragments;
        }

        try {
            ServerKeyExchangeMessage<?> serverKeyExchangeMessage = (ServerKeyExchangeMessage<?>) messages.get(0);
            ServerKeyExchangeBuilder serverKeyExchangeBuilder = new ServerKeyExchangeBuilder(getAnalysisConfig(), getTlsContext(), serverKeyExchangeMessage);

            return serverKeyExchangeBuilder.buildFragmentsForMessage(mergedFragment);
        } catch (OverlappingFragmentException e) {
            LOGGER.error("Encountered error while creating fragments: {}", e.getMessage());
            return originalFragments;
        }
    }

    @Override
    public void analyzeResults() {
        ResultsHandler resultsHandler = new ResultsHandler(
                getAnalysisConfig(),
                getTlsContext(),
                getTrace(),
                getDigestHandler()
        );
        resultsHandler.inspectWorkflowTrace();
        resultsHandler.verifyClientFinishedMessage();

        if (getTlsContext().isReceivedFatalAlert()) {
            LOGGER.info("Received Fatal Alert");
        }
    }
}
