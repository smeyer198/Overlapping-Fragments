package de.upb.cs.message;

import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.SignatureAlgorithmsCertExtensionMessage;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.Field;
import de.upb.cs.config.FragmentConfig;
import de.upb.cs.config.LengthConfig;
import de.upb.cs.config.OffsetConfig;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.OverrideConfig;
import de.upb.cs.analysis.Utils;

import java.util.ArrayList;
import java.util.List;

public class ClientHelloBuilder extends MessageBuilder {

    public ClientHelloBuilder(AnalysisConfig analysisConfig, TlsContext context) {
        super(analysisConfig, context);
    }

    @Override
    public List<DtlsHandshakeMessageFragment> buildFragmentsForMessage() throws OverlappingFragmentException {
        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        ClientHelloMessage clientHelloMessage = new ClientHelloMessage(analysisConfig.getTlsAttackerConfig());
        prepareMessage(clientHelloMessage);
        setHandshakeMessage(clientHelloMessage);
        adjustContext(clientHelloMessage);

        for (FragmentConfig fragmentConfig : analysisConfig.getFragments()) {
            int messageLength = getHandshakeMessage().getLength().getValue();
            int offset = parseOffset(fragmentConfig.getOffset(), messageLength);
            int length = parseLength(fragmentConfig.getLength(), offset, messageLength);

            if (fragmentConfig.getOffsetConfig() != null) {
                offset = parseOffset(fragmentConfig.getOffsetConfig(), messageLength);
            }

            if (fragmentConfig.getLengthConfig() != null) {
                length = parseLength(fragmentConfig.getLengthConfig(), offset, messageLength);
            }

            DtlsHandshakeMessageFragment fragment;
            if (fragmentConfig.getOverrideConfig() != null) {
                int index = parseOverrideIndex(fragmentConfig.getOverrideConfig());
                byte[] byteValue = Utils.hexToByteArray(fragmentConfig.getOverrideConfig().getBytes());

                byte[] manipulatedBytes = fragmentBuilder.overwriteBytes(getHandshakeMessage().getMessageContent().getValue(), index, byteValue);
                fragment = fragmentBuilder.buildFragment(
                        getHandshakeMessage().getHandshakeMessageType(),
                        manipulatedBytes,
                        messageLength,
                        offset,
                        length,
                        getWriteMessageSequence(),
                        fragmentConfig.getPrependBytes(),
                        fragmentConfig.getAppendBytes());
            } else {
                fragment = fragmentBuilder.buildFragment(
                        getHandshakeMessage().getHandshakeMessageType(),
                        getHandshakeMessage().getMessageContent().getValue(),
                        messageLength,
                        offset,
                        length,
                        getWriteMessageSequence(),
                        fragmentConfig.getPrependBytes(),
                        fragmentConfig.getAppendBytes());
            }

            fragments.add(fragment);
        }

        return fragments;
    }

    public int parseOffset(OffsetConfig offsetConfig, int messageLength) throws OverlappingFragmentException {
        Field field = offsetConfig.getField();

        switch (field) {
            case NONE:
                if (offsetConfig.getOffset() < 0) {
                    return messageLength + offsetConfig.getOffset();
                }
                return offsetConfig.getOffset();
            case VERSION:
                return getVersionIndex() + offsetConfig.getOffset();
            case CIPHER_SUITE:
                return getCipherSuiteIndex() + offsetConfig.getOffset();
            case EXTENSION:
                return getExtensionIndex() + offsetConfig.getOffset();
            default:
                throw new OverlappingFragmentException("Field " + field + " from offset is not allowed in ClientHello");
        }
    }

    public int parseLength(LengthConfig lengthConfig, int offset, int messageLength) throws OverlappingFragmentException {
        if (lengthConfig.getLength() == Integer.MIN_VALUE) {
            return lengthConfig.getLength();
        }

        Field field = lengthConfig.getField();
        switch (field) {
            case NONE:
                if (lengthConfig.getLength() < 0) {
                    return messageLength - offset + lengthConfig.getLength();
                }
                return lengthConfig.getLength();
            case VERSION:
                return getVersionIndex() + lengthConfig.getLength();
            case CIPHER_SUITE:
                return getCipherSuiteIndex() + lengthConfig.getLength();
            case EXTENSION:
                return getExtensionIndex() + lengthConfig.getLength();
            default:
                throw new OverlappingFragmentException("Field " + field + " is not allowed in ClientHello");
        }
    }

    public int parseOverrideIndex(OverrideConfig overrideConfig) throws OverlappingFragmentException {
        Field field = overrideConfig.getField();

        switch (field) {
            case NONE:
                return overrideConfig.getIndex();
            case VERSION:
                return getVersionIndex() + overrideConfig.getIndex();
            case CIPHER_SUITE:
                return getCipherSuiteIndex() + overrideConfig.getIndex();
            case EXTENSION:
                return getExtensionIndex() + overrideConfig.getIndex();
            default:
                throw new OverlappingFragmentException("Field " + field + " is not allowed in ClientHello");
        }
    }

    public int getVersionIndex() {
        return 0;
    }

    public int getCipherSuiteIndex() {
        // Version(2) + Random + SessionIDLength(1) + CookieLength(1) + Cookie + CipherSuiteLength(2)
        return 2 + context.getClientRandom().length + 1 + 1 + context.getDtlsCookie().length + 2;
    }

    public int getExtensionIndex() {
        ClientHelloMessage clientHelloMessage = (ClientHelloMessage) getHandshakeMessage();

        int index = 0;
        for (ExtensionMessage<?> extension : clientHelloMessage.getExtensions()) {
            if (extension.getExtensionTypeConstant().equals(ExtensionType.SIGNATURE_AND_HASH_ALGORITHMS)) {
                index += 2 + 6;
                break;
            }

            index += extension.getExtensionBytes().getValue().length;
        }
        // Version(2) + Random + SessionIDLength(1) + CookieLength(1) + Cookie + CipherSuiteLength(2) + CipherSuites + CompressionMethodsLength(1) + CompressionMethods(1) + ExtensionsLength(2) + Type(2), Length(2), SignatureLength(2)
        return 2 + context.getClientRandom().length + 1 + 1 + context.getDtlsCookie().length + 2 + analysisConfig.getClientHelloCipherSuites().size() * 2 + 1 + 1 + index;
    }
}
