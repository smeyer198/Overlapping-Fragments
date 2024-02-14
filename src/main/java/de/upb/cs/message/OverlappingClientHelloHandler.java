package de.upb.cs.message;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.analysis.OverlappingFragmentException;

import java.util.List;

public class OverlappingClientHelloHandler extends OverlappingMessageHandler {

    public OverlappingClientHelloHandler(Config config, OverlappingAnalysisConfig analysisConfig) {
        super(config, analysisConfig);
    }

    @Override
    public List<DtlsHandshakeMessageFragment> createFragmentsFromMessage(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        switch (getOverlappingField()) {
            case CLIENT_HELLO_EMPTY:
                return this.createOverlappingFragmentsForMessage(originalFragment);
            case CLIENT_HELLO_VERSION:
                return this.createOverlappingFragmentsForVersion(originalFragment);
            case CLIENT_HELLO_CIPHER_SUITE:
                return this.createOverlappingFragmentsForCipherSuites(originalFragment, context);
            case CLIENT_HELLO_EXTENSION:
                return this.createOverlappingFragmentsForExtension(originalFragment, context);
            default:
                throw new OverlappingFragmentException("Field " + getOverlappingField() + " is not allowed in ClientHello message");
        }
    }

    private List<DtlsHandshakeMessageFragment> createOverlappingFragmentsForMessage(DtlsHandshakeMessageFragment originalFragment) throws OverlappingFragmentException {
        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), getSplitIndex(), getOverlappingBytes(), getAdditionalFragmentIndex());
    }

    private List<DtlsHandshakeMessageFragment> createOverlappingFragmentsForVersion(DtlsHandshakeMessageFragment originalFragment) throws OverlappingFragmentException {
        int lowerBound = 0;
        int upperBound = 2;

        if (getSplitIndex() < lowerBound || getSplitIndex() > upperBound) {
            throw new OverlappingFragmentException("Index " + getSplitIndex() + " should be between " + lowerBound + " and " + upperBound);
        }

        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), getSplitIndex(), getOverlappingBytes(), getAdditionalFragmentIndex());
    }

    private List<DtlsHandshakeMessageFragment> createOverlappingFragmentsForCipherSuites(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        // Version(2) + Random + SessionIDLength(1) + CookieLength(1) + Cookie + CipherSuiteLength(2)
        int cipherSuiteIndex = 2 + context.getClientRandom().length + 1 + 1 + context.getDtlsCookie().length + 2;
        int lowerBound = 0;
        int upperBound = 2 * getAnalysisConfig().getSupportedCipherSuites().size();

        if (getSplitIndex() < lowerBound || getSplitIndex() > 2 * upperBound) {
            throw new OverlappingFragmentException("Index " + getSplitIndex() + " should be between " + lowerBound + " and " + upperBound);
        }

        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), cipherSuiteIndex + getSplitIndex(), getOverlappingBytes(), getAdditionalFragmentIndex());
    }

    private List<DtlsHandshakeMessageFragment> createOverlappingFragmentsForExtension(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        // Version(2) + Random + SessionIDLength(1) + CookieLength(1) + Cookie + CipherSuiteLength(2) + CipherSuites + CompressionMethodsLength(1) + CompressionMethods + ExtensionsLength(2) + Type(2), Length(2), SignatureLength(2)
        int extensionIndex = 2 + context.getClientRandom().length + 1 + 1 + context.getDtlsCookie().length + 2 + getAnalysisConfig().getSupportedCipherSuites().size() * 2 + 1 + getAnalysisConfig().getSupportedCompressionMethods().size() + 2 + 6;
        int lowerBound = 0;
        int upperBound = 2 * getAnalysisConfig().getSupportedSignatureAndHashAlgorithms().size();

        if (getSplitIndex() < lowerBound || getSplitIndex() > upperBound) {
            throw new OverlappingFragmentException("Index " + getSplitIndex() + " should be between " + lowerBound + " and " + upperBound);
        }

        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), extensionIndex + getSplitIndex(), getOverlappingBytes(), getAdditionalFragmentIndex());
    }
}
