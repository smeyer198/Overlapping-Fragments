package de.upb.cs.message;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.analysis.OverlappingFragmentException;

import java.util.List;

public class OverlappingServerHelloHandler extends OverlappingMessageHandler {

    public OverlappingServerHelloHandler(OverlappingAnalysisConfig analysisConfig) {
        super(analysisConfig);
    }

    @Override
    public List<DtlsHandshakeMessageFragment> createFragmentsFromMessage(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        switch (getOverlappingField()) {
            case SERVER_HELLO:
                return this.createOverlappingFragmentsForMessage(originalFragment);
            case SERVER_HELLO_VERSION:
                return this.createOverlappingFragmentsForVersion(originalFragment);
            case SERVER_HELLO_CIPHER_SUITE:
                return this.createOverlappingFragmentsForCipherSuite(originalFragment, context);
            default:
                throw new OverlappingFragmentException("Field " + getOverlappingField() + " is not allowed in ServerHello message");
        }
    }

    public List<DtlsHandshakeMessageFragment> createOverlappingFragmentsForMessage(DtlsHandshakeMessageFragment originalFragment) throws OverlappingFragmentException {
        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), getSplitIndex(), getOverlappingBytes(), getAdditionalFragmentIndex());
    }

    public List<DtlsHandshakeMessageFragment> createOverlappingFragmentsForVersion(DtlsHandshakeMessageFragment originalFragment) throws OverlappingFragmentException {
        int lowerBound = 0;
        int upperBound = 2;

        if (getSplitIndex() < lowerBound || getSplitIndex() > upperBound) {
            throw new OverlappingFragmentException("Index " + getSplitIndex() + " should be between " + lowerBound + " and " + upperBound);
        }

        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), getSplitIndex(), getOverlappingBytes(), getAdditionalFragmentIndex());
    }

    public List<DtlsHandshakeMessageFragment> createOverlappingFragmentsForCipherSuite(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        // Version(2) + Random + SessionIdLength(1) + SessionId
        int cipherSuiteIndex = 2 + context.getServerRandom().length + 1 + context.getServerSessionId().length;
        int lowerBound = 0;
        int upperBound = 2;

        if (getSplitIndex() < lowerBound || getSplitIndex() > upperBound) {
            throw new OverlappingFragmentException("Index " + getSplitIndex() + " should be between " + lowerBound + " and " + upperBound);
        }

        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), cipherSuiteIndex + getSplitIndex(), getOverlappingBytes(), getAdditionalFragmentIndex());
    }
}
