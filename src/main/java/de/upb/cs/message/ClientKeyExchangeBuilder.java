package de.upb.cs.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
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

public class ClientKeyExchangeBuilder extends MessageBuilder {

    public ClientKeyExchangeBuilder(AnalysisConfig analysisConfig, TlsContext context) {
        super(analysisConfig, context);
    }

    @Override
    public List<DtlsHandshakeMessageFragment> buildFragmentsForMessage() throws OverlappingFragmentException {
        MessageType targetMessageType = analysisConfig.getMessageType();

        switch (targetMessageType) {
            case RSA_CLIENT_KEY_EXCHANGE:
                return buildFragmentsForRSAClientKeyExchange();
            case DH_CLIENT_KEY_EXCHANGE:
                return buildFragmentsForDHClientKeyExchange();
            case ECDH_CLIENT_KEY_EXCHANGE:
                return buildFragmentsForECDHClientKeyExchange();
            default:
                throw new OverlappingFragmentException("Message " + targetMessageType + " is not a ClientKeyExchange message");
        }
    }

    public List<DtlsHandshakeMessageFragment> buildFragmentsForRSAClientKeyExchange() throws OverlappingFragmentException {
        // Follow the same premaster generation as in https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/protocol/preparator/RSAClientKeyExchangePreparator.java
        int keyByteLength = context.getServerRSAModulus().bitLength() / 8;
        int randomByteLength = keyByteLength - 48 - analysisConfig.getServerHelloVersion().getValue().length - 3;
        byte[] padding = new byte[randomByteLength];
        context.getRandom().nextBytes(padding);
        ArrayConverter.makeArrayNonZero(padding);

        // Choose random bytes, maybe use hardcoded bytes instead?
        byte[] premasterSecret = new byte[46];
        context.getRandom().nextBytes(premasterSecret);

        byte[] paddedPremasterSecret = ArrayConverter.concatenate(
                new byte[]{(byte) 0x00, (byte) 0x02},
                padding,
                new byte[]{(byte) 0x00},
                context.getSelectedProtocolVersion().getValue(),
                premasterSecret
        );

        if (analysisConfig.isUseUpdatedKeys()) {
            context.setPreMasterSecret(ArrayConverter.concatenate(context.getSelectedProtocolVersion().getValue(), premasterSecret));
        }

        long seed = 1234567;

        RSAClientKeyExchangeMessage<?> ckeWithOriginalPremasterSecret = new RSAClientKeyExchangeMessage<>();
        prepareMessage(ckeWithOriginalPremasterSecret);
        setHandshakeMessage(ckeWithOriginalPremasterSecret);

        RSAClientKeyExchangeMessage<?> ckeWithUpdatedPremasterSecret = new RSAClientKeyExchangeMessage<>();
        context.getRandom().setSeed(seed);
        prepareMessage(ckeWithUpdatedPremasterSecret);

        byte[] updatedPremasterSecret = ckeWithUpdatedPremasterSecret.getPublicKey().getValue();
        LOGGER.info("Updated RSA Encrypted Premaster Secret:{}", ArrayConverter.bytesToHexString(updatedPremasterSecret));

        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        for (FragmentConfig fragmentConfig : analysisConfig.getFragments()) {
            DtlsHandshakeMessageFragment fragment = createFragmentFromConfig(ckeWithOriginalPremasterSecret, fragmentConfig, updatedPremasterSecret);
            fragments.add(fragment);
        }

        if (analysisConfig.isUseUpdatedKeys()) {
            adjustContext(ckeWithUpdatedPremasterSecret);
        } else {
            adjustContext(ckeWithOriginalPremasterSecret);
        }

        return fragments;
    }

    public List<DtlsHandshakeMessageFragment> buildFragmentsForDHClientKeyExchange() throws OverlappingFragmentException {
        BigInteger privateDhKey = new BigInteger(analysisConfig.getDhPrivateKey(), 16);

        DHClientKeyExchangeMessage<?> ckeWithOriginalPremasterSecret = new DHClientKeyExchangeMessage<>();
        prepareMessage(ckeWithOriginalPremasterSecret);
        setHandshakeMessage(ckeWithOriginalPremasterSecret);

        DHClientKeyExchangeMessage<?> ckeWithUpdatedPremasterSecret = new DHClientKeyExchangeMessage<>();
        context.setClientDhPrivateKey(privateDhKey);
        prepareMessage(ckeWithUpdatedPremasterSecret);

        byte[] updatedPublicKeyBytes = ckeWithUpdatedPremasterSecret.getPublicKey().getValue();
        LOGGER.info("Updated DH Public Key:{}", ArrayConverter.bytesToHexString(updatedPublicKeyBytes));

        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        for (FragmentConfig fragmentConfig : analysisConfig.getFragments()) {
            DtlsHandshakeMessageFragment fragment = createFragmentFromConfig(ckeWithOriginalPremasterSecret, fragmentConfig, updatedPublicKeyBytes);
            fragments.add(fragment);
        }

        if (analysisConfig.isUseUpdatedKeys()) {
            adjustContext(ckeWithUpdatedPremasterSecret);
        } else {
            context.setClientDhPrivateKey(analysisConfig.getTlsAttackerConfig().getDefaultClientDhPrivateKey());
            adjustContext(ckeWithOriginalPremasterSecret);
        }

        return fragments;
    }

    public List<DtlsHandshakeMessageFragment> buildFragmentsForECDHClientKeyExchange() throws OverlappingFragmentException {
        BigInteger privateEcKey = new BigInteger(analysisConfig.getEcPrivateKey());

        ECDHClientKeyExchangeMessage<?> ckeWithOriginalPremasterSecret = new ECDHClientKeyExchangeMessage<>();
        prepareMessage(ckeWithOriginalPremasterSecret);
        setHandshakeMessage(ckeWithOriginalPremasterSecret);

        ECDHClientKeyExchangeMessage<?> ckeWithUpdatedPremasterSecret = new ECDHClientKeyExchangeMessage<>();
        context.setClientEcPrivateKey(privateEcKey);
        prepareMessage(ckeWithUpdatedPremasterSecret);

        byte[] updatedPublicKeyBytes = ckeWithUpdatedPremasterSecret.getPublicKey().getValue();
        LOGGER.info("Updated EC Public Point:{}", ArrayConverter.bytesToHexString(updatedPublicKeyBytes));

        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        for (FragmentConfig fragmentConfig : analysisConfig.getFragments()) {
            DtlsHandshakeMessageFragment fragment = createFragmentFromConfig(ckeWithOriginalPremasterSecret, fragmentConfig, updatedPublicKeyBytes);
            fragments.add(fragment);
        }

        if (analysisConfig.isUseUpdatedKeys()) {
            adjustContext(ckeWithUpdatedPremasterSecret);
        } else {
            context.setClientEcPrivateKey(analysisConfig.getTlsAttackerConfig().getDefaultClientEcPrivateKey());
            adjustContext(ckeWithOriginalPremasterSecret);
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
            length = parseLength(fragmentConfig.getLengthConfig());
        }

        ClientKeyExchangeMessage<?> clientKeyExchangeMessage = (ClientKeyExchangeMessage<?>) message;
        byte[] originalPublicKey = clientKeyExchangeMessage.getPublicKey().getValue();

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

        // TODO This should be done better to allow negative indices
        if (offsetConfig.getOffset() < 0) {
            return messageLength + offsetConfig.getOffset();
        }

        switch (field) {
            case NONE:
                return offsetConfig.getOffset();
            case PUBLIC_KEY:
                if (analysisConfig.getMessageType() == MessageType.RSA_CLIENT_KEY_EXCHANGE) {
                    return getRSAPremasterIndex() + offsetConfig.getOffset();
                } else if (analysisConfig.getMessageType() == MessageType.DH_CLIENT_KEY_EXCHANGE) {
                    return getDHPublicKeyIndex() + offsetConfig.getOffset();
                } else if (analysisConfig.getMessageType() == MessageType.ECDH_CLIENT_KEY_EXCHANGE) {
                    return getECDHPublicKeyIndex() + offsetConfig.getOffset();
                } else {
                    throw new OverlappingFragmentException("Message " + analysisConfig.getMessageType() + " is not allowed in ClientKeyExchange");
                }
            default:
                throw new OverlappingFragmentException("Field " + field + " is not allowed in ClientKeyExchange");
        }
    }

    public int parseLength(LengthConfig lengthConfig) {
        return lengthConfig.getLength();
    }

    public int parseOverrideIndex(OverrideConfig overrideConfig) throws OverlappingFragmentException {
        Field field = overrideConfig.getField();

        switch (field) {
            case NONE:
                return overrideConfig.getIndex();
            case PUBLIC_KEY:
                if (analysisConfig.getMessageType() == MessageType.RSA_CLIENT_KEY_EXCHANGE) {
                    return getRSAPremasterIndex() + overrideConfig.getIndex();
                } else if (analysisConfig.getMessageType() == MessageType.DH_SERVER_KEY_EXCHANGE) {
                    return getDHPublicKeyIndex() + overrideConfig.getIndex();
                } else if (analysisConfig.getMessageType() == MessageType.ECDH_SERVER_KEY_EXCHANGE) {
                    return getECDHPublicKeyIndex() + overrideConfig.getIndex();
                } else {
                    throw new OverlappingFragmentException("Message " + analysisConfig.getMessageType() + " is not allowed in ServerKeyExchange");
                }
            default:
                throw new OverlappingFragmentException("Field " + field + " is not allowed in ClientKeyExchange");
        }
    }

    public int getRSAPremasterIndex() {
        return 2;
    }

    public int getDHPublicKeyIndex() {
        return 2;
    }

    public int getECDHPublicKeyIndex() {
        return 1;
    }

}
