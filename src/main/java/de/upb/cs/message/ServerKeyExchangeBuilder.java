package de.upb.cs.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DHEServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.Constants;
import de.upb.cs.config.Field;
import de.upb.cs.config.FragmentConfig;
import de.upb.cs.config.LengthConfig;
import de.upb.cs.config.Message;
import de.upb.cs.config.OffsetConfig;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.OverrideConfig;
import de.upb.cs.util.LogUtils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class ServerKeyExchangeBuilder extends MessageBuilder {

    private final ServerKeyExchangeMessage<?> serverKeyExchangeMessage;

    public ServerKeyExchangeBuilder(OverlappingAnalysisConfig analysisConfig, TlsContext context, ServerKeyExchangeMessage<?> serverKeyExchangeMessage) {
        super(analysisConfig, context);

        this.serverKeyExchangeMessage = serverKeyExchangeMessage;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> buildFragmentsForMessage(DtlsHandshakeMessageFragment originalFragment) throws OverlappingFragmentException {
        Message message = analysisConfig.getMessage();

        switch (message) {
            case DH_SERVER_KEY_EXCHANGE:
                return buildFragmentsForDHServerKeyExchange(originalFragment);
            case ECDH_SERVER_KEY_EXCHANGE:
                return buildFragmentsForECDHServerKeyExchange(originalFragment);
            default:
                throw new OverlappingFragmentException("Message " + message + " is not a ServerKeyExchange message");
        }
    }

    public List<DtlsHandshakeMessageFragment> buildFragmentsForDHServerKeyExchange(DtlsHandshakeMessageFragment originalFragment) throws OverlappingFragmentException {
        BigInteger privateDhKey = new BigInteger(analysisConfig.getDhPrivateKey(), 16);
        BigInteger publicDhKey = KeyComputation.computeDhPublicKey(privateDhKey, context);
        byte[] publicDhKeyBytes = ArrayConverter.bigIntegerToByteArray(publicDhKey);

        LOGGER.info("Updated DH Public Key:\n{}", ArrayConverter.bytesToHexString(publicDhKeyBytes));

        if (analysisConfig.isUseUpdatedKeys()) {
            context.setServerDhPrivateKey(privateDhKey);
            context.setServerDhPublicKey(publicDhKey);
        }

        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        for (FragmentConfig fragmentConfig : analysisConfig.getFragments()) {
            DtlsHandshakeMessageFragment fragment = createFragmentFromConfig(originalFragment, fragmentConfig, publicDhKeyBytes);
            fragments.add(fragment);
        }
        return fragments;
    }

    public List<DtlsHandshakeMessageFragment> buildFragmentsForECDHServerKeyExchange(DtlsHandshakeMessageFragment originalFragment) throws OverlappingFragmentException {
        NamedGroup group = context.getChooser().getSelectedNamedGroup();
        BigInteger privateEcKey = new BigInteger(analysisConfig.getEcPrivateKey());
        Point publicEcKey = KeyComputation.computeEcPublicKey(privateEcKey, group);
        byte[] publicEcKeyBytes = PointFormatter.formatToByteArray(group, publicEcKey, analysisConfig.getServerHelloPointFormat());

        LOGGER.info("Updated EC Public Point:\n{}", ArrayConverter.bytesToHexString(publicEcKeyBytes));

        if (analysisConfig.isUseUpdatedKeys()) {
            context.setServerEcPrivateKey(privateEcKey);
            context.setServerEcPublicKey(publicEcKey);
        }

        List<DtlsHandshakeMessageFragment> fragments = new ArrayList<>();

        for (FragmentConfig fragmentConfig : analysisConfig.getFragments()) {
            DtlsHandshakeMessageFragment fragment = createFragmentFromConfig(originalFragment, fragmentConfig, publicEcKeyBytes);
            fragments.add(fragment);
        }
        return fragments;
    }

    public DtlsHandshakeMessageFragment createFragmentFromConfig(DtlsHandshakeMessageFragment originalFragment, FragmentConfig fragmentConfig, byte[] publicKey) throws OverlappingFragmentException {
        int messageLength = originalFragment.getFragmentContentConfig().length;
        int offset = parseOffset(fragmentConfig.getOffset(), messageLength);
        int length = parseLength(fragmentConfig.getLength(), offset, messageLength);

        if (fragmentConfig.getOffsetConfig() != null) {
            offset = parseOffset(fragmentConfig.getOffsetConfig(), messageLength);
        }

        if (fragmentConfig.getLengthConfig() != null) {
            length = parseLength(fragmentConfig.getLengthConfig(), offset, messageLength);
        }

        byte[] originalPublicKey = serverKeyExchangeMessage.getPublicKey().getOriginalValue();

        if (fragmentConfig.getAppendBytes().equals(Constants.ORIGINAL_PUBLIC_KEY_LABEL)) {
            return fragmentBuilder.buildFragment(originalFragment, offset, length, new byte[]{}, originalPublicKey);
        } else if (fragmentConfig.getPrependBytes().equals(Constants.ORIGINAL_PUBLIC_KEY_LABEL)) {
            return fragmentBuilder.buildFragment(originalFragment, offset, length, originalPublicKey, new byte[]{});
        } else if (fragmentConfig.getAppendBytes().equals(Constants.MANIPULATED_PUBLIC_KEY_LABEL)) {
            return fragmentBuilder.buildFragment(originalFragment, offset, length, new byte[]{}, publicKey);
        } else if (fragmentConfig.getPrependBytes().equals(Constants.MANIPULATED_PUBLIC_KEY_LABEL)) {
            return fragmentBuilder.buildFragment(originalFragment, offset, length, publicKey, new byte[]{});
        }

        if (fragmentConfig.getOverrideConfig() != null) {
            if (fragmentConfig.getOverrideConfig().getBytes().equals(Constants.ORIGINAL_PUBLIC_KEY_LABEL)) {
                return fragmentBuilder.buildFragment(originalFragment, offset, length, fragmentConfig.getPrependBytes(), fragmentConfig.getAppendBytes());
            } else if (fragmentConfig.getOverrideConfig().getBytes().equals(Constants.MANIPULATED_PUBLIC_KEY_LABEL)) {
                int startIndex = parseOverrideIndex(fragmentConfig.getOverrideConfig());
                DtlsHandshakeMessageFragment manipulatedFragment = fragmentBuilder.overwriteBytes(originalFragment, startIndex, publicKey);

                return fragmentBuilder.buildFragment(manipulatedFragment, offset, length, fragmentConfig.getPrependBytes(), fragmentConfig.getAppendBytes());
            } else {
                int index = parseOverrideIndex(fragmentConfig.getOverrideConfig());
                byte[] byteValue = LogUtils.hexToByteArray(fragmentConfig.getOverrideConfig().getBytes());

                DtlsHandshakeMessageFragment manipulatedFragment = fragmentBuilder.overwriteBytes(originalFragment, index, byteValue);
                return fragmentBuilder.buildFragment(manipulatedFragment, offset, length, fragmentConfig.getPrependBytes(), fragmentConfig.getAppendBytes());
            }
        }

        return fragmentBuilder.buildFragment(originalFragment, offset, length, fragmentConfig.getPrependBytes(), fragmentConfig.getAppendBytes());
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
                if (analysisConfig.getMessage() == Message.DH_SERVER_KEY_EXCHANGE) {
                    return getDHPublicKeyIndex() + offsetConfig.getOffset();
                } else if (analysisConfig.getMessage() == Message.ECDH_SERVER_KEY_EXCHANGE) {
                    return getECDHPublicKeyIndex() + offsetConfig.getOffset();
                } else {
                    throw new OverlappingFragmentException("Message " + analysisConfig.getMessage() + " is not allowed in ServerKeyExchange");
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
                if (analysisConfig.getMessage() == Message.DH_SERVER_KEY_EXCHANGE) {
                    return getDHPublicKeyIndex() + lengthConfig.getLength();
                } else if (analysisConfig.getMessage() == Message.ECDH_SERVER_KEY_EXCHANGE) {
                    return getECDHPublicKeyIndex() + lengthConfig.getLength();
                } else {
                    throw new OverlappingFragmentException("Message " + analysisConfig.getMessage() + " is not allowed in ServerKeyExchange");
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
                if (analysisConfig.getMessage() == Message.DH_SERVER_KEY_EXCHANGE) {
                    return getDHPublicKeyIndex() + overrideConfig.getIndex();
                } else if (analysisConfig.getMessage() == Message.ECDH_SERVER_KEY_EXCHANGE) {
                    return getECDHPublicKeyIndex() + overrideConfig.getIndex();
                } else {
                    throw new OverlappingFragmentException("Message " + analysisConfig.getMessage() + " is not allowed in ServerKeyExchange");
                }
            default:
                throw new OverlappingFragmentException("Field " + field + " is not allowed in ServerKeyExchange");
        }
    }

    public int getDHPublicKeyIndex() {
        // Modulus Length (2) + Modulus + Generator Length (2) + Generator + Public Key Length (2)
        int pLength = ((DHEServerKeyExchangeMessage<?>) serverKeyExchangeMessage).getModulusLength().getOriginalValue();
        int gLength = ((DHEServerKeyExchangeMessage<?>) serverKeyExchangeMessage).getGeneratorLength().getOriginalValue();

        return 2 + pLength + 2 + gLength + 2;
    }

    public int getECDHPublicKeyIndex() {
        // Curve Type (1) + Named Curve (2) + Public Key Length (1)
        return 1 + 2 + 1;
    }
}
