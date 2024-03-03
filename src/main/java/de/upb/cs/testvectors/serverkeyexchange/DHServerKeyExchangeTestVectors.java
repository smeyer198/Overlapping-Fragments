package de.upb.cs.testvectors.serverkeyexchange;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

public class DHServerKeyExchangeTestVectors {

    private static final CipherSuite serverHelloCipherSuite = CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
    private static final String privateKey = "FEFE";

    public static OverlappingAnalysisConfig noOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_KEY_EXCHANGE);
        fieldConfig.setOverlappingType(OverlappingType.NO_OVERLAPPING_TYPE);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setDhPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_KEY_EXCHANGE_DH);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setDhPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_KEY_EXCHANGE_DH);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setDhPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_KEY_EXCHANGE_DH);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setDhPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_KEY_EXCHANGE_DH);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setDhPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_KEY_EXCHANGE_DH);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setDhPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_KEY_EXCHANGE_DH);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setDhPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_KEY_EXCHANGE_DH);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        analysisConfig.setDhPrivateKey(privateKey);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.SERVER_KEY_EXCHANGE_DH);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setDhPrivateKey(privateKey);
        analysisConfig.setServerHelloCipherSuite(serverHelloCipherSuite);
        return analysisConfig;
    }
}
