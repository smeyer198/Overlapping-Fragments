package de.upb.cs.analysis;

import de.rub.nds.tlsattacker.core.protocol.message.CertificateMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.CertificateVerifyMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloDoneMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeProtocolVersionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.upb.cs.action.AdvancedChangeCipherSuiteAction;
import de.upb.cs.action.ReceiveDynamicServerKeyExchangeAction;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.Constants;
import de.upb.cs.config.MessageType;
import de.upb.cs.message.ClientHelloBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ClientHelloAnalysis extends AbstractAnalysis {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientHelloAnalysis.class);
    private final ClientHelloBuilder clientHelloBuilder;

    public ClientHelloAnalysis(AnalysisConfig analysisConfig) throws OverlappingFragmentException {
        super(analysisConfig, Constants.CLIENT_CONTEXT);

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(getConfig());
        this.clientHelloBuilder = new ClientHelloBuilder(getAnalysisConfig(), getTlsContext(), clientHelloMessage);
    }

    @Override
    public void initializeWorkflowTrace() {
        if (isCookieExchange()) {
            if (getAnalysisConfig().getMessageType() == MessageType.INITIAL_CLIENT_HELLO) {
                addSendFragmentsActionToTrace(clientHelloBuilder);
            } else {
                getTrace().addTlsAction(new SendAction(getAliasContext(), new ClientHelloMessage(getConfig())));
            }
            getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new HelloVerifyRequestMessage()));
        }

        if (getAnalysisConfig().getMessageType() == MessageType.CLIENT_HELLO) {
            addSendFragmentsActionToTrace(clientHelloBuilder);
        } else {
            getTrace().addTlsAction(new SendAction(getAliasContext(), new ClientHelloMessage(getConfig())));
        }
        //getTrace().addTlsAction(new SendAction(getAliasContext(), new ClientHelloMessage(getConfig())));

        if (getAnalysisConfig().getUpdateProtocolVersion() != null) {
            ChangeProtocolVersionAction protocolVersionAction = new ChangeProtocolVersionAction(getAnalysisConfig().getUpdateProtocolVersion());
            protocolVersionAction.setConnectionAlias(getAliasContext());
            getTrace().addTlsAction(protocolVersionAction);
        }

        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new ServerHelloMessage()));
        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new CertificateMessage()));
        getTrace().addTlsAction(new ReceiveDynamicServerKeyExchangeAction(getAliasContext()));

        if (isClientAuthentication()) {
            getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new CertificateRequestMessage()));
        }

        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new ServerHelloDoneMessage()));

        if (getAnalysisConfig().getUpdateCipherSuite() != null) {
            getTrace().addTlsAction(new AdvancedChangeCipherSuiteAction(getAliasContext(), getAnalysisConfig().getUpdateCipherSuite()));
        }

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
    public void analyzeResults() {
        ResultsHandler resultsHandler = new ResultsHandler(
                getAnalysisConfig(),
                getTlsContext(),
                getTrace(),
                getDigestHandler()
        );
        resultsHandler.inspectWorkflowTrace();
        resultsHandler.inspectHandshakeParameters();

        resultsHandler.verifyServerFinishedMessage();

        if (getTlsContext().isReceivedFatalAlert()) {
            LOGGER.info("Received Fatal Alert");
        }
    }
}
