package de.upb.cs.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.Constants;
import de.upb.cs.config.Field;
import de.upb.cs.config.FragmentConfig;
import de.upb.cs.config.LengthConfig;
import de.upb.cs.config.MessageType;
import de.upb.cs.config.OffsetConfig;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.OverrideConfig;
import de.upb.cs.analysis.Utils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class ClientKeyExchangeBuilder extends MessageBuilder {

    public ClientKeyExchangeBuilder(AnalysisConfig analysisConfig, TlsContext context) {
        super(analysisConfig, context);
    }

    @Override
    public List<DtlsHandshakeMessageFragment> buildFragmentsForMessage(HandshakeMessage<?> message) throws OverlappingFragmentException {
        MessageType targetMessageType = analysisConfig.getMessageType();

        switch (targetMessageType) {
            case RSA_CLIENT_KEY_EXCHANGE:
                return buildFragmentsForRSAClientKeyExchange(message);
            case DH_CLIENT_KEY_EXCHANGE:
                return buildFragmentsForDHClientKeyExchange(message);
            case ECDH_CLIENT_KEY_EXCHANGE:
                return buildFragmentsForECDHClientKeyExchange(message);
            default:
                throw new OverlappingFragmentException("Message " + targetMessageType + " is not a ClientKeyExchange message");
        }
    }

    public List<DtlsHandshakeMessageFragment> buildFragmentsForRSAClientKeyExchange(HandshakeMessage<?> message) throws OverlappingFragmentException {
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

        BigInteger biPaddedPremasterSecret = new BigInteger(1, paddedPremasterSecret);
        BigInteger biEncrypted = biPaddedPremasterSecret.modPow(context.getServerRSAPublicKey().abs(), context.getServerRSAModulus().abs());
        byte[] rsaEncryptedPremasterSecret = ArrayConverter.bigIntegerToByteArray(biEncrypted, context.getServerRSAModulus().bitLength() / 8, true);

        LOGGER.info("Updated RSA Encrypted Premaster Secret:{}", ArrayConverter.bytesToHexString(rsaEncryptedPremasterSecret));

        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        for (FragmentConfig fragmentConfig : analysisConfig.getFragments()) {
            DtlsHandshakeMessageFragment fragment = createFragmentFromConfig(message, fragmentConfig, rsaEncryptedPremasterSecret);
            fragments.add(fragment);
        }

        return fragments;
    }

    public List<DtlsHandshakeMessageFragment> buildFragmentsForDHClientKeyExchange(HandshakeMessage<?> message) throws OverlappingFragmentException {
        BigInteger privateDhKey = new BigInteger(analysisConfig.getDhPrivateKey(), 16);
        BigInteger publicDhKey = KeyComputation.computeDhPublicKey(privateDhKey, context);
        byte[] publicDhKeyBytes = ArrayConverter.bigIntegerToByteArray(publicDhKey);

        LOGGER.info("Updated DH Public Key:{}", ArrayConverter.bytesToHexString(publicDhKeyBytes));

        if (analysisConfig.isUseUpdatedKeys()) {
            context.setClientDhPrivateKey(privateDhKey);
            context.setClientDhPublicKey(publicDhKey);
        }

        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        for (FragmentConfig fragmentConfig : analysisConfig.getFragments()) {
            DtlsHandshakeMessageFragment fragment = createFragmentFromConfig(message, fragmentConfig, publicDhKeyBytes);
            fragments.add(fragment);
        }

        return fragments;
    }

    public List<DtlsHandshakeMessageFragment> buildFragmentsForECDHClientKeyExchange(HandshakeMessage<?> message) throws OverlappingFragmentException {
        NamedGroup group = context.getChooser().getSelectedNamedGroup();
        BigInteger privateEcKey = new BigInteger(analysisConfig.getEcPrivateKey());
        Point publicEcKey = KeyComputation.computeEcPublicKey(privateEcKey, group);
        byte[] publicEcKeyBytes = PointFormatter.formatToByteArray(group, publicEcKey, analysisConfig.getServerHelloPointFormat());

        LOGGER.info("Updated EC Public Point:{}", ArrayConverter.bytesToHexString(publicEcKeyBytes));

        if (analysisConfig.isUseUpdatedKeys()) {
            context.setServerEcPrivateKey(privateEcKey);
            context.setServerEcPublicKey(publicEcKey);
        }

        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        for (FragmentConfig fragmentConfig : analysisConfig.getFragments()) {
            DtlsHandshakeMessageFragment fragment = createFragmentFromConfig(message, fragmentConfig, publicEcKeyBytes);
            fragments.add(fragment);
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

        ClientKeyExchangeMessage<?> clientKeyExchangeMessage = (ClientKeyExchangeMessage<?>) getHandshakeMessage();
        byte[] originalPublicKey = clientKeyExchangeMessage.getPublicKey().getOriginalValue();

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

    public int parseOffset(OffsetConfig offsetConfig, int messageLength) {
        if (offsetConfig.getOffset() < 0) {
            return messageLength + offsetConfig.getOffset();
        }
        return offsetConfig.getOffset();
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
                throw new OverlappingFragmentException("Field " + field + " is not allowed in ServerKeyExchange");
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

    public void setClientKeyExchangeMessage(ClientKeyExchangeMessage<?> clientKeyExchangeMessage) {
        setHandshakeMessage(clientKeyExchangeMessage);
    }
}
