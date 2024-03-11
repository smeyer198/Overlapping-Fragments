package de.upb.cs.analysis;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.dtls.FragmentInterceptor;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.message.DigestHandler;
import de.upb.cs.util.LogUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public abstract  class AbstractAnalysis {

    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractAnalysis.class);
    private final OverlappingAnalysisConfig analysisConfig;
    private final String aliasContext;
    private final WorkflowTrace trace;
    private final State state;
    private final DigestHandler digestHandler;

    public AbstractAnalysis(OverlappingAnalysisConfig analysisConfig,String aliasContext) throws OverlappingFragmentException {
        this.analysisConfig = analysisConfig;
        this.aliasContext = aliasContext;

        AliasedConnection connection;
        if (aliasContext.equals("client")) {
            connection = analysisConfig.getTlsAttackerConfig().getDefaultClientConnection();
        } else if (aliasContext.equals("server")) {
            connection = analysisConfig.getTlsAttackerConfig().getDefaultServerConnection();
        } else {
            throw new OverlappingFragmentException("Alias context should be either 'client' or 'server'");
        }

        this.trace = new WorkflowTrace(List.of(connection));
        this.state = new State(analysisConfig.getTlsAttackerConfig(), trace);
        this.digestHandler = new DigestHandler();

        this.state.getTlsContext().setFragmentInterceptor(new FragmentInterceptor() {
            @Override
            public List<DtlsHandshakeMessageFragment> interceptFragments(HandshakeMessageType type, byte[] handshakeBytes, List<DtlsHandshakeMessageFragment> originalFragments) {
                if (originalFragments.isEmpty()) {
                    return originalFragments;
                }

                if (analysisConfig.getOverlappingField() == OverlappingField.NO_FIELD) {
                    return originalFragments;
                }

                DtlsHandshakeMessageFragment originalFragment;
                if (originalFragments.size() != 1) {
                    originalFragment = getSingleFragment(originalFragments, handshakeBytes);
                } else {
                    originalFragment = originalFragments.get(0);
                }

                List<DtlsHandshakeMessageFragment> overlappingFragments = fragmentMessage(type, originalFragment, originalFragments);

                // No overlapping fragments were created
                if (originalFragments.equals(overlappingFragments)) {
                    return originalFragments;
                }

                digestHandler.updateManipulatedMessageBytes(originalFragment.getFragmentContentConfig(), overlappingFragments);
                if (isOverlappingBytesInDigest()) {
                    LOGGER.debug("Updating digest for message of type {}", type);
                    DigestHandler.updateLastDigestBytesInContext(getTlsContext(), getDigestHandler().getManipulatedMessageBytes());
                }

                LogUtils.logOverlappingFragments(originalFragment, overlappingFragments);

                return overlappingFragments;
            }
        });

        LOGGER.info("Using FieldConfig\n{}", analysisConfig.getOverlappingFieldConfig());
    }

    public abstract void initializeWorkflowTrace();

    protected abstract List<DtlsHandshakeMessageFragment> fragmentMessage(final HandshakeMessageType handshakeMessageType, DtlsHandshakeMessageFragment mergedFragment, List<DtlsHandshakeMessageFragment> originalFragments);

    public abstract void analyzeResults();

    private DtlsHandshakeMessageFragment getSingleFragment(List<DtlsHandshakeMessageFragment> fragments, byte[] handshakeBytes) {
        // All fragments belong to the same message
        DtlsHandshakeMessageFragment fragment = fragments.get(0);

        return new DtlsHandshakeMessageFragment(
                fragment.getHandshakeMessageTypeConfig(),
                handshakeBytes,
                fragment.getMessageSequenceConfig(),
                0,
                fragment.getHandshakeMessageLengthConfig()
        );
    }

    public OverlappingAnalysisConfig getAnalysisConfig() {
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

    public boolean isOverlappingBytesInDigest() {
        return analysisConfig.isOverlappingBytesInDigest();
    }

    public boolean isCookieExchange() {
        return analysisConfig.isCookieExchange();
    }

}
