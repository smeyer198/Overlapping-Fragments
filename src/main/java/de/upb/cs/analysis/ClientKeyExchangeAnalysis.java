package de.upb.cs.analysis;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.upb.cs.action.ReceiveDynamicServerKeyExchangeAction;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.message.ClientKeyExchangeBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public class ClientKeyExchangeAnalysis extends AbstractAnalysis {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientKeyExchangeAnalysis.class);
    private final SendDynamicClientKeyExchangeAction dynamicClientKeyExchangeAction;

    public ClientKeyExchangeAnalysis(OverlappingAnalysisConfig analysisConfig) throws OverlappingFragmentException {
        super(analysisConfig, "client");

        this.dynamicClientKeyExchangeAction = new SendDynamicClientKeyExchangeAction(getAliasContext());
    }

    @Override
    public void initializeWorkflowTrace() {
        if (isCookieExchange()) {
            getTrace().addTlsAction(new SendAction(getAliasContext(), new ClientHelloMessage(getConfig())));
            getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new HelloVerifyRequestMessage()));
        }

        getTrace().addTlsAction(new SendAction(getAliasContext(), new ClientHelloMessage(getConfig())));
        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new ServerHelloMessage()));
        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new CertificateMessage()));
        getTrace().addTlsAction(new ReceiveDynamicServerKeyExchangeAction(getAliasContext()));

        if (isClientAuthentication()) {
            getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new CertificateRequestMessage()));
        }

        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new ServerHelloDoneMessage()));

        if (isClientAuthentication()) {
            getTrace().addTlsAction(new SendAction(getAliasContext(), new CertificateMessage()));
        }

        getTrace().addTlsAction(dynamicClientKeyExchangeAction);

        if (isClientAuthentication()) {
            getTrace().addTlsAction(new SendAction(getAliasContext(), new CertificateVerifyMessage()));
        }

        getTrace().addTlsAction(new SendAction(getAliasContext(), new ChangeCipherSpecMessage()));
        getTrace().addTlsAction(new SendAction(getAliasContext(), new FinishedMessage()));
        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new ChangeCipherSpecMessage()));
        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new FinishedMessage()));
    }

    @Override
    protected List<DtlsHandshakeMessageFragment> fragmentMessage(HandshakeMessageType handshakeMessageType, DtlsHandshakeMessageFragment mergedFragment, List<DtlsHandshakeMessageFragment> originalFragments) {
        if (handshakeMessageType != HandshakeMessageType.CLIENT_KEY_EXCHANGE) {
            return originalFragments;
        }

        List<ProtocolMessage> messages = dynamicClientKeyExchangeAction.getSendMessages();
        if (messages.isEmpty()) {
            return originalFragments;
        }

        try {
            ClientKeyExchangeMessage<?> clientKeyExchangeMessage = (ClientKeyExchangeMessage<?>) messages.get(0);
            ClientKeyExchangeBuilder clientKeyExchangeBuilder = new ClientKeyExchangeBuilder(getAnalysisConfig(), getTlsContext(), clientKeyExchangeMessage);

            return clientKeyExchangeBuilder.buildFragmentsForMessage(mergedFragment);
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
        resultsHandler.verifyServerFinishedMessage();

        if (getTlsContext().isReceivedFatalAlert()) {
            LOGGER.info("Received Fatal Alert");
        }
    }
}
