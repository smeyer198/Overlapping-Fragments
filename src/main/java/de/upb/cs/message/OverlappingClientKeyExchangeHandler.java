package de.upb.cs.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.util.LogUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class OverlappingClientKeyExchangeHandler extends OverlappingMessageHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(OverlappingClientKeyExchangeHandler.class);

    public OverlappingClientKeyExchangeHandler(Config config, OverlappingAnalysisConfig analysisConfig) {
        super(config, analysisConfig);
    }

    @Override
    public List<DtlsHandshakeMessageFragment> createFragmentsFromMessage(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        switch (getOverlappingField()) {
            case CLIENT_KEY_EXCHANGE:
                return this.createOverlappingFragmentsForMessage(originalFragment);
            case CLIENT_KEY_EXCHANGE_RSA:
                return this.createFragmentsForRSAClientKeyExchangeMessage(originalFragment, context);
            case CLIENT_KEY_EXCHANGE_DH:
                return this.createFragmentsForDHClientKeyExchange(originalFragment, context);
            case CLIENT_KEY_EXCHANGE_ECDH:
                return this.createFragmentsForECDHClientKeyExchange(originalFragment, context);
            default:
                throw new OverlappingFragmentException("Field " + getOverlappingField() + " is not allowed in ClientKeyExchange message");
        }
    }

    public List<DtlsHandshakeMessageFragment> createOverlappingFragmentsForMessage(DtlsHandshakeMessageFragment originalFragment) throws OverlappingFragmentException {
        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), getSplitIndex(), getOverlappingBytes(), getAdditionalFragmentIndex());
    }

    public List<DtlsHandshakeMessageFragment> createFragmentsForRSAClientKeyExchangeMessage(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        if (getSplitIndex() != 2) {
            throw new OverlappingFragmentException("Index " + getOverlappingOrder() + " has to be 2");
        }

        byte[] updatedRSAPremasterSecret = this.computeUpdatedRSAPremasterSecret(context);

        LOGGER.debug("Updated RSA Premaster Secret: {}", LogUtils.byteToHexString(updatedRSAPremasterSecret));
        getOverlappingFieldConfig().setOverlappingBytes(updatedRSAPremasterSecret);

        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), getSplitIndex(), updatedRSAPremasterSecret, getAdditionalFragmentIndex());
    }

    public byte[] computeUpdatedRSAPremasterSecret(TlsContext context) {
        // Follow the same premaster generation as in https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/protocol/preparator/RSAClientKeyExchangePreparator.java
        int keyByteLength = context.getServerRSAModulus().bitLength() / 8;
        int randomByteLength = keyByteLength - 48 - getAnalysisConfig().getServerHelloVersion().getValue().length - 3;
        byte[] padding = new byte[randomByteLength];
        context.getRandom().nextBytes(padding);
        ArrayConverter.makeArrayNonZero(padding);

        // Choose random bytes, maybe use hardcoded bytes instead?
        byte[] premaster_secret = new byte[46];
        context.getRandom().nextBytes(premaster_secret);

        byte[] paddedPremasterSecret = ArrayConverter.concatenate(
                new byte[]{(byte) 0x00, (byte) 0x02},
                padding,
                new byte[]{(byte) 0x00},
                getAnalysisConfig().getServerHelloVersion().getValue(),
                premaster_secret
        );
        if (getAnalysisConfig().isUseUpdatedKeys()) {
            getConfig().setDefaultPreMasterSecret(ArrayConverter.concatenate(getAnalysisConfig().getServerHelloVersion().getValue(), premaster_secret));
        }

        BigInteger biPaddedPremasterSecret = new BigInteger(1, paddedPremasterSecret);
        BigInteger biEncrypted = biPaddedPremasterSecret.modPow(context.getServerRSAPublicKey().abs(), context.getServerRSAModulus().abs());

        return ArrayConverter.bigIntegerToByteArray(biEncrypted, context.getServerRSAModulus().bitLength() / 8, true);
    }

    public List<DtlsHandshakeMessageFragment> createFragmentsForDHClientKeyExchange(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        if (getSplitIndex() != 2) {
            throw new OverlappingFragmentException("Index " + getSplitIndex() + " has to be 2");
        }

        BigInteger privateDhKey = new BigInteger(getAnalysisConfig().getDhPrivateKey(), 16);
        BigInteger publicDhKey = KeyComputation.computeDhPublicKey(privateDhKey, context);
        byte[] publicDhKeyBytes = ArrayConverter.bigIntegerToByteArray(publicDhKey);

        LOGGER.debug("Updated DH Public Key: {}", LogUtils.byteToHexString(publicDhKeyBytes));
        getOverlappingFieldConfig().setOverlappingBytes(publicDhKeyBytes);

        if (getAnalysisConfig().isUseUpdatedKeys()) {
            context.setServerDhPrivateKey(privateDhKey);
            context.setServerDhPublicKey(publicDhKey);
        }

        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), getSplitIndex(), publicDhKeyBytes, getAdditionalFragmentIndex());
    }

    public List<DtlsHandshakeMessageFragment> createFragmentsForECDHClientKeyExchange(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        if (getSplitIndex() != 1 && getSplitIndex() != 2) {
            throw new OverlappingFragmentException("Index " + getSplitIndex() + " has to be 1 or 2");
        }

        NamedGroup group = context.getChooser().getSelectedNamedGroup();
        BigInteger privateEcKey = new BigInteger(getAnalysisConfig().getEcPrivateKey());
        Point publicEcKey = KeyComputation.computeEcPublicKey(privateEcKey, group);
        byte[] publicEcKeyBytes = PointFormatter.formatToByteArray(group, publicEcKey, getAnalysisConfig().getServerHelloPointFormat());

        LOGGER.debug("Updated EC Public Point: {}", LogUtils.byteToHexString(publicEcKeyBytes));
        getOverlappingFieldConfig().setOverlappingBytes(publicEcKeyBytes);

        if (getAnalysisConfig().isUseUpdatedKeys()) {
            context.setServerEcPrivateKey(privateEcKey);
            context.setServerEcPublicKey(publicEcKey);
        }

        LOGGER.debug("Remove first byte from Public Point");
        publicEcKeyBytes = Arrays.copyOfRange(publicEcKeyBytes, 1, publicEcKeyBytes.length);

        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), getSplitIndex(), publicEcKeyBytes, getAdditionalFragmentIndex());
    }

}
