package de.upb.cs.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.analysis.Utils;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.Constants;
import de.upb.cs.config.Field;
import de.upb.cs.config.FragmentConfig;
import de.upb.cs.config.LengthConfig;
import de.upb.cs.config.MessageType;
import de.upb.cs.config.OffsetConfig;
import de.upb.cs.config.OverrideConfig;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class ServerKeyExchangeBuilder extends MessageBuilder {

    public ServerKeyExchangeBuilder(AnalysisConfig analysisConfig, TlsContext context) {
        super(analysisConfig, context);
    }

    @Override
    public List<DtlsHandshakeMessageFragment> buildFragmentsForMessage() throws OverlappingFragmentException {
        MessageType targetMessageType = analysisConfig.getMessageType();

        switch (targetMessageType) {
            case DH_SERVER_KEY_EXCHANGE:
                return buildFragmentsForDHServerKeyExchange();
            case ECDH_SERVER_KEY_EXCHANGE:
                return buildFragmentsForECDHServerKeyExchange();
            default:
                throw new OverlappingFragmentException("Message " + targetMessageType + " is not a ServerKeyExchange message");
        }
    }

    public List<DtlsHandshakeMessageFragment> buildFragmentsForDHServerKeyExchange() throws OverlappingFragmentException {
        BigInteger privateDhKey = new BigInteger(analysisConfig.getDhPrivateKey(), 16);

        DHEServerKeyExchangeMessage<?> skeWithOriginalPublicKey = new DHEServerKeyExchangeMessage<>();
        prepareMessage(skeWithOriginalPublicKey);
        setHandshakeMessage(skeWithOriginalPublicKey);

        DHEServerKeyExchangeMessage<?> skeWithUpdatedPublicKey = new DHEServerKeyExchangeMessage<>();
        context.setServerDhPrivateKey(privateDhKey);
        prepareMessage(skeWithUpdatedPublicKey);

        byte[] updatedPublicKeyBytes = skeWithUpdatedPublicKey.getPublicKey().getValue();
        LOGGER.info("Updated DH Public Key:\n{}", ArrayConverter.bytesToHexString(updatedPublicKeyBytes));

        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        for (FragmentConfig fragmentConfig : analysisConfig.getFragments()) {
            DtlsHandshakeMessageFragment fragment = createFragmentFromConfig(skeWithOriginalPublicKey, fragmentConfig, updatedPublicKeyBytes);
            fragments.add(fragment);
        }

        if (analysisConfig.isUseUpdatedKeys()) {
            adjustContext(skeWithUpdatedPublicKey);
        } else {
            context.setServerDhPrivateKey(analysisConfig.getTlsAttackerConfig().getDefaultServerDhPrivateKey());
            adjustContext(skeWithOriginalPublicKey);
        }

        return fragments;
    }

    public List<DtlsHandshakeMessageFragment> buildFragmentsForECDHServerKeyExchange() throws OverlappingFragmentException {
        BigInteger privateEcKey = new BigInteger(analysisConfig.getEcPrivateKey());

        ECDHEServerKeyExchangeMessage<?> skeWithOriginalPublicKey = new ECDHEServerKeyExchangeMessage<>();
        prepareMessage(skeWithOriginalPublicKey);
        setHandshakeMessage(skeWithOriginalPublicKey);

        ECDHEServerKeyExchangeMessage<?> skeWithUpdatedPublicKey = new ECDHEServerKeyExchangeMessage<>();
        context.setServerEcPrivateKey(privateEcKey);
        prepareMessage(skeWithUpdatedPublicKey);

        byte[] updatedPublicKeyBytes = skeWithUpdatedPublicKey.getPublicKey().getValue();
        LOGGER.info("Updated EC Public Point:\n{}", ArrayConverter.bytesToHexString(updatedPublicKeyBytes));

        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        for (FragmentConfig fragmentConfig : analysisConfig.getFragments()) {
            DtlsHandshakeMessageFragment fragment = createFragmentFromConfig(skeWithOriginalPublicKey, fragmentConfig, updatedPublicKeyBytes);
            fragments.add(fragment);
        }

        if (analysisConfig.isUseUpdatedKeys()) {
            adjustContext(skeWithUpdatedPublicKey);
        } else {
            context.setServerEcPrivateKey(analysisConfig.getTlsAttackerConfig().getDefaultServerEcPrivateKey());
            adjustContext(skeWithOriginalPublicKey);
        }

        return fragments;
    }

    public DtlsHandshakeMessageFragment createFragmentFromConfig(HandshakeMessage<?> message, FragmentConfig fragmentConfig, byte[] publicKey) throws OverlappingFragmentException {
        int messageLength = message.getLength().getValue();
        int offset = parseOffset(fragmentConfig.getOffset(), messageLength);
        int length = parseLength(fragmentConfig.getLength(), offset, messageLength);

        if (fragmentConfig.getOffsetConfig() != null) {
            offset = parseOffset(fragmentConfig.getOffsetConfig(), messageLength);
        }

        if (fragmentConfig.getLengthConfig() != null) {
            length = parseLength(fragmentConfig.getLengthConfig(), offset, messageLength);
        }

        ServerKeyExchangeMessage<?> serverKeyExchangeMessage = (ServerKeyExchangeMessage<?>) getHandshakeMessage();
        byte[] originalPublicKey = serverKeyExchangeMessage.getPublicKey().getValue();

        if (fragmentConfig.getAppendBytes().equals(Constants.ORIGINAL_PUBLIC_KEY_LABEL)) {
            return fragmentBuilder.buildFragment(
                    message.getHandshakeMessageType(),
                    message.getMessageContent().getValue(),
                    messageLength,
                    offset,
                    length,
                    getWriteMessageSequence(),
                    new byte[]{},
                    originalPublicKey);
        } else if (fragmentConfig.getPrependBytes().equals(Constants.ORIGINAL_PUBLIC_KEY_LABEL)) {
            return fragmentBuilder.buildFragment(
                    message.getHandshakeMessageType(),
                    message.getMessageContent().getValue(),
                    messageLength,
                    offset,
                    length,
                    getWriteMessageSequence(),
                    originalPublicKey,
                    new byte[]{});
        } else if (fragmentConfig.getAppendBytes().equals(Constants.MANIPULATED_PUBLIC_KEY_LABEL)) {
            return fragmentBuilder.buildFragment(
                    message.getHandshakeMessageType(),
                    message.getMessageContent().getValue(),
                    messageLength,
                    offset,
                    length,
                    getWriteMessageSequence(),
                    new byte[]{},
                    publicKey);
        } else if (fragmentConfig.getPrependBytes().equals(Constants.MANIPULATED_PUBLIC_KEY_LABEL)) {
            return fragmentBuilder.buildFragment(
                    message.getHandshakeMessageType(),
                    message.getMessageContent().getValue(),
                    messageLength,
                    offset,
                    length,
                    getWriteMessageSequence(),
                    publicKey,
                    new byte[]{});
        }

        if (fragmentConfig.getOverrideConfig() != null) {
            if (fragmentConfig.getOverrideConfig().getBytes().equals(Constants.ORIGINAL_PUBLIC_KEY_LABEL)) {
                return fragmentBuilder.buildFragment(
                        message.getHandshakeMessageType(),
                        message.getMessageContent().getValue(),
                        messageLength,
                        offset,
                        length,
                        getWriteMessageSequence(),
                        fragmentConfig.getPrependBytes(),
                        fragmentConfig.getAppendBytes());
            } else if (fragmentConfig.getOverrideConfig().getBytes().equals(Constants.MANIPULATED_PUBLIC_KEY_LABEL)) {
                int startIndex = parseOverrideIndex(fragmentConfig.getOverrideConfig());
                byte[] manipulatedBytes = fragmentBuilder.overwriteBytes(message.getMessageContent().getValue(), startIndex, publicKey);

                return fragmentBuilder.buildFragment(
                        message.getHandshakeMessageType(),
                        manipulatedBytes,
                        messageLength,
                        offset,
                        length,
                        getWriteMessageSequence(),
                        fragmentConfig.getPrependBytes(),
                        fragmentConfig.getAppendBytes());
            } else {
                int index = parseOverrideIndex(fragmentConfig.getOverrideConfig());
                byte[] byteValue = Utils.hexToByteArray(fragmentConfig.getOverrideConfig().getBytes());

                byte[] manipulatedBytes = fragmentBuilder.overwriteBytes(message.getMessageContent().getValue(), index, byteValue);
                return fragmentBuilder.buildFragment(
                        message.getHandshakeMessageType(),
                        manipulatedBytes,
                        messageLength,
                        offset,
                        length,
                        getWriteMessageSequence(),
                        fragmentConfig.getPrependBytes(),
                        fragmentConfig.getAppendBytes());
            }
        }

        return fragmentBuilder.buildFragment(
                message.getHandshakeMessageType(),
                message.getMessageContent().getValue(),
                messageLength,
                offset,
                length,
                getWriteMessageSequence(),
                fragmentConfig.getPrependBytes(),
                fragmentConfig.getAppendBytes());
    }

    public int parseOffset(OffsetConfig offsetConfig, int messageLength) throws OverlappingFragmentException {
        Field field = offsetConfig.getField();

        switch (field) {
            case NONE:
                if (offsetConfig.getOffset() < 0) {
                    return messageLength + offsetConfig.getOffset();
                }
                return offsetConfig.getOffset();
            case PUBLIC_KEY:
                if (analysisConfig.getMessageType() == MessageType.DH_SERVER_KEY_EXCHANGE) {
                    return getDHPublicKeyIndex() + offsetConfig.getOffset();
                } else if (analysisConfig.getMessageType() == MessageType.ECDH_SERVER_KEY_EXCHANGE) {
                    return getECDHPublicKeyIndex() + offsetConfig.getOffset();
                } else {
                    throw new OverlappingFragmentException("Message " + analysisConfig.getMessageType() + " is not allowed in ServerKeyExchange");
                }
            default:
                throw new OverlappingFragmentException("Field " + field + " is not allowed in ServerKeyExchange");
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
            case PUBLIC_KEY:
                if (analysisConfig.getMessageType() == MessageType.DH_SERVER_KEY_EXCHANGE) {
                    return getDHPublicKeyIndex() + lengthConfig.getLength();
                } else if (analysisConfig.getMessageType() == MessageType.ECDH_SERVER_KEY_EXCHANGE) {
                    return getECDHPublicKeyIndex() + lengthConfig.getLength();
                } else {
                    throw new OverlappingFragmentException("Message " + analysisConfig.getMessageType() + " is not allowed in ServerKeyExchange");
                }
        }
        return lengthConfig.getLength();
    }

    public int parseOverrideIndex(OverrideConfig overrideConfig) throws OverlappingFragmentException {
        Field field = overrideConfig.getField();

        switch (field) {
            case NONE:
                return overrideConfig.getIndex();
            case PUBLIC_KEY:
                if (analysisConfig.getMessageType() == MessageType.DH_SERVER_KEY_EXCHANGE) {
                    return getDHPublicKeyIndex() + overrideConfig.getIndex();
                } else if (analysisConfig.getMessageType() == MessageType.ECDH_SERVER_KEY_EXCHANGE) {
                    return getECDHPublicKeyIndex() + overrideConfig.getIndex();
                } else {
                    throw new OverlappingFragmentException("Message " + analysisConfig.getMessageType() + " is not allowed in ServerKeyExchange");
                }
            default:
                throw new OverlappingFragmentException("Field " + field + " is not allowed in ServerKeyExchange");
        }
    }

    public int getDHPublicKeyIndex() {
        // Modulus Length (2) + Modulus + Generator Length (2) + Generator + Public Key Length (2)
        int pLength = ((DHEServerKeyExchangeMessage<?>) getHandshakeMessage()).getModulusLength().getOriginalValue();
        int gLength = ((DHEServerKeyExchangeMessage<?>) getHandshakeMessage()).getGeneratorLength().getOriginalValue();

        return 2 + pLength + 2 + gLength + 2;
    }

    public int getECDHPublicKeyIndex() {
        // Curve Type (1) + Named Curve (2) + Public Key Length (1)
        return 1 + 2 + 1;
    }
}
