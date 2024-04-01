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
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicServerKeyExchangeAction;
import de.upb.cs.action.AdvancedChangeCipherSuiteAction;
import de.upb.cs.action.ReceiveDynamicClientKeyExchangeAction;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.Constants;
import de.upb.cs.message.ServerHelloBuilder;

public class ServerHelloAnalysis extends AbstractAnalysis {

    private final ServerHelloBuilder serverHelloBuilder;

    public ServerHelloAnalysis(AnalysisConfig analysisConfig) throws OverlappingFragmentException {
        super(analysisConfig, Constants.SERVER_CONTEXT);

        ServerHelloMessage serverHelloMessage = new ServerHelloMessage(getConfig());
        this.serverHelloBuilder = new ServerHelloBuilder(getAnalysisConfig(), getTlsContext(), serverHelloMessage);
    }

    @Override
    public void initializeWorkflowTrace() {
        if (isCookieExchange()) {
            getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new ClientHelloMessage()));
            getTrace().addTlsAction(new SendAction(getAliasContext(), new HelloVerifyRequestMessage()));
        }

        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new ClientHelloMessage()));
        //getTrace().addTlsAction(new SendFragmentsAction(getAliasContext(), serverHelloBuilder));
        addSendFragmentsActionToTrace(serverHelloBuilder);

        if (getAnalysisConfig().getUpdateProtocolVersion() != null) {
            ChangeProtocolVersionAction protocolVersionAction = new ChangeProtocolVersionAction(getAnalysisConfig().getUpdateProtocolVersion());
            protocolVersionAction.setConnectionAlias(getAliasContext());
            getTrace().addTlsAction(protocolVersionAction);
        }

        getTrace().addTlsAction(new SendAction(getAliasContext(), new CertificateMessage()));
        getTrace().addTlsAction(new SendDynamicServerKeyExchangeAction(getAliasContext()));

        if (isClientAuthentication()) {
            getTrace().addTlsAction(new SendAction(getAliasContext(), new CertificateRequestMessage()));
        }

        getTrace().addTlsAction(new SendAction(getAliasContext(), new ServerHelloDoneMessage()));

        if (getAnalysisConfig().getUpdateCipherSuite() != null) {
            getTrace().addTlsAction(new AdvancedChangeCipherSuiteAction(getAliasContext(), getAnalysisConfig().getUpdateCipherSuite()));
        }

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
    public AnalysisResults analyzeResults() {
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

        return resultsHandler.getResults();
    }
}
