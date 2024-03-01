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
import de.upb.cs.config.OverlappingType;
import de.upb.cs.util.LogUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.util.List;

public class OverlappingServerKeyExchangeHandler extends OverlappingMessageHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(OverlappingServerKeyExchangeHandler.class);

    public OverlappingServerKeyExchangeHandler(Config config, OverlappingAnalysisConfig analysisConfig) {
        super(config, analysisConfig);
    }

    @Override
    public List<DtlsHandshakeMessageFragment> createFragmentsFromMessage(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        switch (getOverlappingField()) {
            case SERVER_KEY_EXCHANGE:
                return createOverlappingFragmentsForMessage(originalFragment);
            case SERVER_KEY_EXCHANGE_DH:
                return createFragmentsForDHServerKeyExchangeMessage(originalFragment, context);
            case SERVER_KEY_EXCHANGE_ECDH:
                return createFragmentsForECDHServerKeyExchangeMessage(originalFragment, context);
            default:
                throw new OverlappingFragmentException("Field " + getOverlappingField() + " is not allowed in ServerKeyExchange message");
        }
    }

    public List<DtlsHandshakeMessageFragment> createOverlappingFragmentsForMessage(DtlsHandshakeMessageFragment originalFragment) throws OverlappingFragmentException {
        return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), getSplitIndex(), getOverlappingBytes(), getAdditionalFragmentIndex());
    }

    public List<DtlsHandshakeMessageFragment> createFragmentsForDHServerKeyExchangeMessage(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        // Modulus Length (2) + Modulus + Generator Length (2) + Generator + Public Key Length (2)
        int pLength = context.getChooser().getServerDhModulus().bitLength() / 8;
        int gLength = String.valueOf(context.getChooser().getServerDhGenerator().intValue()).length();
        int publicKeyIndex = 2 + pLength + 2 + gLength + 2;

        BigInteger privateDhKey = new BigInteger(getAnalysisConfig().getDhPrivateKey(), 16);
        BigInteger publicDhKey = KeyComputation.computeDhPublicKey(privateDhKey, context);
        byte[] publicDhKeyBytes = ArrayConverter.bigIntegerToByteArray(publicDhKey);

        LOGGER.debug("Updated DH Public Key: {}", LogUtils.byteToHexString(publicDhKeyBytes));
        getOverlappingFieldConfig().setOverlappingBytes(publicDhKeyBytes);

        if (getAnalysisConfig().isUseUpdatedKeys()) {
            context.setServerDhPrivateKey(privateDhKey);
            context.setServerDhPublicKey(publicDhKey);
        }

        if (getOverlappingType() == OverlappingType.CONSECUTIVE_TYPE_A) {
            return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), publicKeyIndex + publicDhKeyBytes.length, publicDhKeyBytes, getAdditionalFragmentIndex());
        } else {
            return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), publicKeyIndex, publicDhKeyBytes, getAdditionalFragmentIndex());
        }
    }

    public List<DtlsHandshakeMessageFragment> createFragmentsForECDHServerKeyExchangeMessage(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        // Curve Type (1) + Named Curve (2) + Public Key Length (1)
        int publicKeyIndex = 1 + 2 + 1;

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

        if (getOverlappingType() == OverlappingType.CONSECUTIVE_TYPE_A) {
            return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), publicKeyIndex + publicEcKeyBytes.length, publicEcKeyBytes, getAdditionalFragmentIndex());
        } else {
            return OverlappingFragmentBuilder.buildOverlappingFragments(originalFragment, getOverlappingType(), getOverlappingOrder(), publicKeyIndex, publicEcKeyBytes, getAdditionalFragmentIndex());
        }
    }
}
