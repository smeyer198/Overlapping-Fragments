package de.upb.cs.analysis;

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
import de.rub.nds.tlsattacker.core.workflow.action.ChangeProtocolVersionAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendDynamicClientKeyExchangeAction;
import de.upb.cs.action.AdvancedChangeCipherSuiteAction;
import de.upb.cs.action.ReceiveDynamicServerKeyExchangeAction;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.message.OverlappingClientHelloHandler;
import de.upb.cs.util.LogUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

public class ClientHelloAnalysis extends AbstractAnalysis {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientHelloAnalysis.class);
    private final OverlappingClientHelloHandler clientHelloHandler;

    public ClientHelloAnalysis(OverlappingAnalysisConfig analysisConfig) throws OverlappingFragmentException {
        super(analysisConfig, "client");

        this.clientHelloHandler = new OverlappingClientHelloHandler(getAnalysisConfig());
    }

    @Override
    public void initializeWorkflowTrace() {
        if (isCookieExchange()) {
            getTrace().addTlsAction(new SendAction(getAliasContext(), new ClientHelloMessage(getConfig())));
            getTrace().addTlsAction(new ReceiveAction(getAliasContext(), new HelloVerifyRequestMessage()));
        }

        getTrace().addTlsAction(new SendAction(getAliasContext(), new ClientHelloMessage(getConfig())));

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
    protected List<DtlsHandshakeMessageFragment> fragmentMessage(HandshakeMessageType handshakeMessageType, DtlsHandshakeMessageFragment mergedFragment, List<DtlsHandshakeMessageFragment> originalFragments) {
        if (handshakeMessageType != HandshakeMessageType.CLIENT_HELLO) {
            return originalFragments;
        }

        /* Relevant for PionDTLS
        if (getTlsContext().getDtlsCookie().length == 0) {
            updateMessageContent(mergedFragment);
            return new ArrayList<>(List.of(mergedFragment));
        }*/

        // Check, whether the first CH message should be fragmented
        if (skipFragmentingFirstMessage()) {
            return originalFragments;
        }

        try {
            return clientHelloHandler.createFragmentsFromMessage(mergedFragment, getTlsContext());
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
        resultsHandler.inspectHandshakeParameters();

        resultsHandler.verifyServerFinishedMessage();
    }

    private boolean skipFragmentingFirstMessage() {
        byte[] cookie = getTlsContext().getDtlsCookie();
        return cookie.length == 0 && !getAnalysisConfig().isFragmentFirstCHMessage();
    }

    public void updateMessageContent(DtlsHandshakeMessageFragment fragment) {
        byte[] fragmentContent = fragment.getFragmentContentConfig();
        fragmentContent[39] = (byte) 0x2b;
        fragment.setFragmentContentConfig(fragmentContent);
        LOGGER.info(LogUtils.byteToHexString(fragmentContent));
        LOGGER.info(LogUtils.byteToHexString(fragment.getFragmentContentConfig()));
    }
}
