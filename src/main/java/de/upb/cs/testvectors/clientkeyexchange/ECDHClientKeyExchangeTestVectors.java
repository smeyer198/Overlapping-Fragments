package de.upb.cs.testvectors.clientkeyexchange;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

import java.util.Arrays;
import java.util.List;

public class ECDHClientKeyExchangeTestVectors {

    private static final int splitIndex = 2;
    private static final List<CipherSuite> cipherSuites = Arrays.asList(
            //CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            //CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    );
    private static final String privateKey = "5";

    private static final List<NamedGroup> supportedGroups = Arrays.asList(
            NamedGroup.SECP256R1,
            NamedGroup.SECP256K1
    );

    private static final List<ECPointFormat> pointFormat = List.of(ECPointFormat.UNCOMPRESSED);

    private static final List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = Arrays.asList(
            SignatureAndHashAlgorithm.ECDSA_SHA256,
            SignatureAndHashAlgorithm.RSA_SHA256
    );

    public static OverlappingAnalysisConfig noOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_KEY_EXCHANGE_ECDH);
        fieldConfig.setOverlappingType(OverlappingType.NO_OVERLAPPING_TYPE);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setAddEllipticCurveExtension(true);
        analysisConfig.setClientHelloGroups(supportedGroups);
        analysisConfig.setAddECPointFormatExtension(true);
        analysisConfig.setClientHelloPointFormats(pointFormat);
        analysisConfig.setEcPrivateKey(privateKey);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);

        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_KEY_EXCHANGE_ECDH);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(splitIndex);
        fieldConfig.setAdditionalFragmentIndex(1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setAddEllipticCurveExtension(true);
        analysisConfig.setClientHelloGroups(supportedGroups);
        analysisConfig.setAddECPointFormatExtension(true);
        analysisConfig.setClientHelloPointFormats(pointFormat);
        analysisConfig.setEcPrivateKey(privateKey);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);

        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_KEY_EXCHANGE_ECDH);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(splitIndex);
        fieldConfig.setAdditionalFragmentIndex(1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setAddEllipticCurveExtension(true);
        analysisConfig.setClientHelloGroups(supportedGroups);
        analysisConfig.setAddECPointFormatExtension(true);
        analysisConfig.setClientHelloPointFormats(pointFormat);
        analysisConfig.setEcPrivateKey(privateKey);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);

        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_KEY_EXCHANGE_ECDH);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(splitIndex);
        fieldConfig.setAdditionalFragmentIndex(1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setAddEllipticCurveExtension(true);
        analysisConfig.setClientHelloGroups(supportedGroups);
        analysisConfig.setAddECPointFormatExtension(true);
        analysisConfig.setClientHelloPointFormats(pointFormat);
        analysisConfig.setEcPrivateKey(privateKey);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);

        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_KEY_EXCHANGE_ECDH);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(splitIndex);
        fieldConfig.setAdditionalFragmentIndex(1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setAddEllipticCurveExtension(true);
        analysisConfig.setClientHelloGroups(supportedGroups);
        analysisConfig.setAddECPointFormatExtension(true);
        analysisConfig.setClientHelloPointFormats(pointFormat);
        analysisConfig.setEcPrivateKey(privateKey);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);

        return analysisConfig;
    }
}
