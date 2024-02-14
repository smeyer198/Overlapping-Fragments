package de.upb.cs.analysis;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
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
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.upb.cs.action.ReceiveDynamicServerKeyExchangeAction;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.message.OverlappingClientKeyExchangeHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.List;

public class ClientKeyExchangeAnalysis extends AbstractAnalysis {

    private static final Logger LOGGER = LogManager.getLogger();
    private final OverlappingClientKeyExchangeHandler clientKeyExchangeHandler;

    public ClientKeyExchangeAnalysis(Config config, OverlappingAnalysisConfig analysisConfig) throws OverlappingFragmentException {
        super(config, "client", analysisConfig);

        this.clientKeyExchangeHandler = new OverlappingClientKeyExchangeHandler(getConfig(), getAnalysisConfig());
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
        getTrace().addTlsAction(new SendDynamicClientKeyExchangeAction(getAliasContext()));
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

        try {
            return clientKeyExchangeHandler.createFragmentsFromMessage(mergedFragment, getTlsContext());
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

        if (getTlsContext().isReceivedFatalAlert()) {
            LOGGER.info("Received Fatal Alert");
        }
    }
}
