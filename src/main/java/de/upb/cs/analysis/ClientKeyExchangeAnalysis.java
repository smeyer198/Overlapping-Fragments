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
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.upb.cs.action.ReceiveDynamicServerKeyExchangeAction;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.Constants;
import de.upb.cs.message.ClientKeyExchangeBuilder;

public class ClientKeyExchangeAnalysis extends AbstractAnalysis {

    private final ClientKeyExchangeBuilder clientKeyExchangeBuilder;

    public ClientKeyExchangeAnalysis(AnalysisConfig analysisConfig) throws OverlappingFragmentException {
        super(analysisConfig, Constants.CLIENT_CONTEXT);

        this.clientKeyExchangeBuilder = new ClientKeyExchangeBuilder(getAnalysisConfig(), getTlsContext());
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

        addSendFragmentsActionToTrace(clientKeyExchangeBuilder);

        if (isClientAuthentication()) {
            getTrace().addTlsAction(new SendAction(getAliasContext(), new CertificateVerifyMessage()));
        }

        getTrace().addTlsAction(new SendAction(getAliasContext(), new ChangeCipherSpecMessage()));
        getTrace().addTlsAction(new SendAction(getAliasContext(), new FinishedMessage()));
        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new ChangeCipherSpecMessage()));
        getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new FinishedMessage()));
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
        resultsHandler.inspectHandshakeParameters();

        resultsHandler.verifyServerFinishedMessage();

        if (getTlsContext().isReceivedFatalAlert()) {
            LOGGER.info("Received Fatal Alert");
        }

        return resultsHandler.getResults();
    }
}
