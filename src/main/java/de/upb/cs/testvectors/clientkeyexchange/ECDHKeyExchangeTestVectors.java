package de.upb.cs.testvectors.clientkeyexchange;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.ConnectionConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class ECDHKeyExchangeTestVectors {

    private static final int splitIndex = 1;
    private static final List<CipherSuite> cipherSuites = Arrays.asList(
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            //CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            //CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    );
    private static final BigInteger privateKey = new BigInteger("5");

    private static final List<NamedGroup> supportedGroups = Arrays.asList(
            NamedGroup.SECP256R1,
            NamedGroup.SECP256K1
    );

    private static final List<ECPointFormat> pointFormat = List.of(ECPointFormat.UNCOMPRESSED);

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_ECDH,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.ORIGINAL,
                splitIndex,
                new byte[]{},
                1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);

        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setAddEllipticCurveExtension(true);
        analysisConfig.setSupportedGroups(supportedGroups);
        analysisConfig.setAddECPointFormatExtension(true);
        analysisConfig.setSupportedPointFormats(pointFormat);
        analysisConfig.setClientEcPrivateKey(privateKey);

        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_ECDH,
                OverlappingType.SUBSEQUENT_TYPE_A,
                OverlappingOrder.REVERSED,
                splitIndex
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);

        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setAddEllipticCurveExtension(true);
        analysisConfig.setSupportedGroups(supportedGroups);
        analysisConfig.setAddECPointFormatExtension(true);
        analysisConfig.setSupportedPointFormats(pointFormat);
        analysisConfig.setClientEcPrivateKey(privateKey);

        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_ECDH,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.ORIGINAL,
                splitIndex,
                new byte[]{},
                1
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);

        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setAddEllipticCurveExtension(true);
        analysisConfig.setSupportedGroups(supportedGroups);
        analysisConfig.setAddECPointFormatExtension(true);
        analysisConfig.setSupportedPointFormats(pointFormat);
        analysisConfig.setClientEcPrivateKey(privateKey);

        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrder(ConnectionConfig connectionConfig) {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig(
                OverlappingField.CLIENT_KEY_EXCHANGE_ECDH,
                OverlappingType.SUBSEQUENT_TYPE_B,
                OverlappingOrder.REVERSED,
                splitIndex
        );

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(connectionConfig, fieldConfig);

        analysisConfig.setSupportedCipherSuites(cipherSuites);
        analysisConfig.setAddEllipticCurveExtension(true);
        analysisConfig.setSupportedGroups(supportedGroups);
        analysisConfig.setAddECPointFormatExtension(true);
        analysisConfig.setSupportedPointFormats(pointFormat);
        analysisConfig.setClientEcPrivateKey(privateKey);

        return analysisConfig;
    }
}
