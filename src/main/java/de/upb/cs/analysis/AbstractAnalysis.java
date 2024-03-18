package de.upb.cs.analysis;

import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.certificate.PemUtil;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.upb.cs.action.SendFragmentsAction;
import de.upb.cs.action.UpdateDigestAction;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.Constants;
import de.upb.cs.message.MessageBuilder;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.List;

public abstract class AbstractAnalysis {

    protected static final Logger LOGGER = LoggerFactory.getLogger(AbstractAnalysis.class);
    private final AnalysisConfig analysisConfig;
    private final String aliasContext;
    private final WorkflowTrace trace;
    private final State state;
    private final DigestHandler digestHandler;

    public AbstractAnalysis(AnalysisConfig analysisConfig, String aliasContext) throws OverlappingFragmentException {
        this.analysisConfig = analysisConfig;
        this.aliasContext = aliasContext;

        AliasedConnection connection;
        if (aliasContext.equals("client")) {
            connection = analysisConfig.getTlsAttackerConfig().getDefaultClientConnection();
        } else if (aliasContext.equals("server")) {
            connection = analysisConfig.getTlsAttackerConfig().getDefaultServerConnection();
        } else {
            throw new OverlappingFragmentException("Alias context must be either '" + Constants.CLIENT_CONTEXT  + "' or '" + Constants.SERVER_CONTEXT + "'");
        }

        this.trace = new WorkflowTrace(List.of(connection));
        this.state = new State(analysisConfig.getTlsAttackerConfig(), trace);
        this.digestHandler = new DigestHandler();

        Config config = analysisConfig.getTlsAttackerConfig();

        CertificateKeyPair keyPair = loadCertificate();
        if (keyPair != null) {
            config.setDefaultExplicitCertificateKeyPair(keyPair);
            config.setAutoSelectCertificate(false);
        }
    }

    private CertificateKeyPair loadCertificate() {
        if (analysisConfig.getCertificatePath().isEmpty() && analysisConfig.getCertificateKeyPath().isEmpty()) {
            LOGGER.debug("Using certificate from TLS-Attacker");
            return null;
        }

        try {
            Security.addProvider(new BouncyCastleProvider());

            Certificate certificate = PemUtil.readCertificate(new File(analysisConfig.getCertificatePath()));
            PrivateKey key = PemUtil.readPrivateKey(new File(analysisConfig.getCertificateKeyPath()));

            return new CertificateKeyPair(certificate, key);
        } catch (CertificateException | IOException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public void addSendFragmentsActionToTrace(MessageBuilder messageBuilder) {
        SendFragmentsAction sendFragmentsAction = new SendFragmentsAction(aliasContext, messageBuilder);
        trace.addTlsAction(sendFragmentsAction);

        UpdateDigestAction updateDigestAction = new UpdateDigestAction(aliasContext, digestHandler, messageBuilder, sendFragmentsAction.getFragments(), analysisConfig.isOverlappingBytesInDigest());
        trace.addTlsAction(updateDigestAction);
    }

    public abstract void initializeWorkflowTrace();

    public abstract void analyzeResults();

    public AnalysisConfig getAnalysisConfig() {
        return analysisConfig;
    }

    public String getAliasContext() {
        return aliasContext;
    }

    public State getState() {
        return state;
    }

    public Config getConfig() {
        return state.getConfig();
    }

    public TlsContext getTlsContext() {
        return state.getTlsContext();
    }

    public WorkflowTrace getTrace() {
        return trace;
    }

    public DigestHandler getDigestHandler() {
        return digestHandler;
    }

    public boolean isClientAuthentication() {
        return analysisConfig.isClientAuthentication();
    }

    public boolean isCookieExchange() {
        return analysisConfig.isCookieExchange();
    }

}
