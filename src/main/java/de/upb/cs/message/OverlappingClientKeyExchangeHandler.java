package de.upb.cs.message;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.analysis.OverlappingFragmentException;

import java.math.BigInteger;
import java.util.List;

public class OverlappingClientKeyExchangeHandler extends OverlappingMessageHandler {

    public OverlappingClientKeyExchangeHandler(Config config, OverlappingAnalysisConfig analysisConfig) {
        super(config, analysisConfig);
    }

    @Override
    public List<DtlsHandshakeMessageFragment> createFragmentsFromMessage(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        switch (getOverlappingField()) {
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

    public List<DtlsHandshakeMessageFragment> createFragmentsForRSAClientKeyExchangeMessage(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        if (getSplitIndex() != 2) {
            throw new OverlappingFragmentException("Index " + getOverlappingOrder() + " has to be 2");
        }

        byte[] updatedRSAPremasterSecret = this.computeUpdatedRSAPremasterSecret(context);
        getOverlappingFieldConfig().setOverlappingBytes(updatedRSAPremasterSecret);

        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), getSplitIndex(), updatedRSAPremasterSecret, getAdditionalFragmentIndex());
    }

    private byte[] computeUpdatedRSAPremasterSecret(TlsContext context) {
        // Follow the same premaster generation as in https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/protocol/preparator/RSAClientKeyExchangePreparator.java
        int keyByteLength = context.getServerRSAModulus().bitLength() / 8;
        int randomByteLength = keyByteLength - 48 - getAnalysisConfig().getDtlsVersion().getValue().length - 3;
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
                getAnalysisConfig().getDtlsVersion().getValue(),
                premaster_secret
        );
        if (getAnalysisConfig().isOverridePremasterSecret()) {
            getConfig().setDefaultPreMasterSecret(ArrayConverter.concatenate(getAnalysisConfig().getDtlsVersion().getValue(), premaster_secret));
        }

        BigInteger biPaddedPremasterSecret = new BigInteger(1, paddedPremasterSecret);
        BigInteger biEncrypted = biPaddedPremasterSecret.modPow(context.getServerRSAPublicKey().abs(), context.getServerRSAModulus().abs());

        return ArrayConverter.bigIntegerToByteArray(biEncrypted, context.getServerRSAModulus().bitLength() / 8, true);
    }

    public List<DtlsHandshakeMessageFragment> createFragmentsForDHClientKeyExchange(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        if (getSplitIndex() != 2) {
            throw new OverlappingFragmentException("Index " + getSplitIndex() + " has to be 2");
        }

        byte[] updatedDHPublicKey = this.computeUpdatedDHPublicKey(context);
        getOverlappingFieldConfig().setOverlappingBytes(updatedDHPublicKey);

        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), getSplitIndex(), updatedDHPublicKey, getAdditionalFragmentIndex());
    }

    private byte[] computeUpdatedDHPublicKey(TlsContext context) {
        // Follow the same computation as in https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/protocol/preparator/DHClientKeyExchangePreparator.java
        BigInteger generator = context.getServerDhGenerator();
        BigInteger modulus = context.getServerDhModulus();

        BigInteger privateKey = getAnalysisConfig().getClientDhPrivateKey();
        if (getAnalysisConfig().isOverridePremasterSecret()) {
            getConfig().setDefaultClientDhPrivateKey(privateKey);
        }

        BigInteger publicKey = generator.modPow(privateKey.abs(), modulus.abs());

        return ArrayConverter.bigIntegerToByteArray(publicKey);
    }

    public List<DtlsHandshakeMessageFragment> createFragmentsForECDHClientKeyExchange(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        if (getSplitIndex() != 1) {
            throw new OverlappingFragmentException("Index " + getSplitIndex() + " has to be 1");
        }

        byte[] updatedECPublicPoint = this.computeUpdatedECPublicPoint(context);
        getOverlappingFieldConfig().setOverlappingBytes(updatedECPublicPoint);

        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), getSplitIndex(), updatedECPublicPoint, getAdditionalFragmentIndex());
    }

    public byte[] computeUpdatedECPublicPoint(TlsContext context) {
        // Follow the generation as in https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/protocol/preparator/ECDHClientKeyExchangePreparator.java
        // TODO Distinguish between context and config: https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/workflow/chooser/DefaultChooser.java#L637
        NamedGroup group = context.getSelectedGroup();
        EllipticCurve curve = CurveFactory.getCurve(group);

        BigInteger privateKey = getAnalysisConfig().getClientEcPrivateKey();
        if (getAnalysisConfig().isOverridePremasterSecret()) {
            getConfig().setDefaultClientEcPrivateKey(privateKey);
        }

        Point publicKeyPoint = curve.mult(privateKey, curve.getBasePoint());
        Point publicKey = curve.getPoint(publicKeyPoint.getFieldX().getData(), publicKeyPoint.getFieldY().getData());

        return PointFormatter.formatToByteArray(group, publicKey, getAnalysisConfig().getSelectedPointFormat());
    }
}
