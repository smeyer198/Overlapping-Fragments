package de.upb.cs.testvectors.clienthello;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

import java.util.Arrays;
import java.util.List;

public class CHExtensionTestVectors {

    //  ECDSA_SHA256(0x0403)
    //private static final byte[] signatureAndHashAlgorithm = new byte[]{(byte) 0x04, (byte) 0x03, (byte) 0x04, (byte) 0x03};
    private static final String signatureAndHashAlgorithm = "04 03 04 03";
    private static final String overlappingByte = "03";
    private static final List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = Arrays.asList(
            SignatureAndHashAlgorithm.RSA_SHA256,
            SignatureAndHashAlgorithm.ECDSA_SHA256
    );
    private static final List<CipherSuite> cipherSuites = Arrays.asList(
            //CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
    );
    private static final List<NamedGroup> supportedGroups = Arrays.asList(
            NamedGroup.SECP256R1
    );

    public static OverlappingAnalysisConfig noOverlappingBytesOriginalOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO);
        fieldConfig.setOverlappingType(OverlappingType.NO_OVERLAPPING_TYPE);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(0);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        analysisConfig.setAddEllipticCurveExtension(false);
        analysisConfig.setClientHelloGroups(supportedGroups);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig noOverlappingBytesReversedOrder() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO);
        fieldConfig.setOverlappingType(OverlappingType.NO_OVERLAPPING_TYPE);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(0);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        analysisConfig.setAddEllipticCurveExtension(false);
        analysisConfig.setClientHelloGroups(supportedGroups);
        return analysisConfig;
    }

    /* ------------------------------------ Single byte ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(2);
        fieldConfig.setOverlappingBytes(overlappingByte);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        analysisConfig.setAddEllipticCurveExtension(false);
        analysisConfig.setClientHelloGroups(supportedGroups);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(2);
        fieldConfig.setOverlappingBytes(overlappingByte);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(overlappingByte);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(overlappingByte);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(overlappingByte);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(1);
        fieldConfig.setOverlappingBytes(overlappingByte);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(overlappingByte);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderSingleOverlappingByte() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(overlappingByte);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }
    /* ------------------------------------ Single byte ------------------------------------ */

    /* ------------------------------------ Multiple bytes ------------------------------------ */
    public static OverlappingAnalysisConfig consecutiveTypeAOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(4);
        fieldConfig.setOverlappingBytes(signatureAndHashAlgorithm);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeAReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(4);
        fieldConfig.setOverlappingBytes(signatureAndHashAlgorithm);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(signatureAndHashAlgorithm);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig consecutiveTypeBReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.CONSECUTIVE_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(signatureAndHashAlgorithm);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(signatureAndHashAlgorithm);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeAReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_A);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(signatureAndHashAlgorithm);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBOriginalOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.ORIGINAL);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(signatureAndHashAlgorithm);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }

    public static OverlappingAnalysisConfig subsequentTypeBReversedOrderMultipleOverlappingBytes() {
        OverlappingFieldConfig fieldConfig = new OverlappingFieldConfig();
        fieldConfig.setOverlappingField(OverlappingField.CLIENT_HELLO_EXTENSION);
        fieldConfig.setOverlappingType(OverlappingType.SUBSEQUENT_TYPE_B);
        fieldConfig.setOverlappingOrder(OverlappingOrder.REVERSED);
        fieldConfig.setSplitIndex(0);
        fieldConfig.setOverlappingBytes(signatureAndHashAlgorithm);
        fieldConfig.setAdditionalFragmentIndex(-1);

        OverlappingAnalysisConfig analysisConfig = new OverlappingAnalysisConfig(fieldConfig);
        analysisConfig.setClientHelloCipherSuites(cipherSuites);
        analysisConfig.setClientHelloSignatureAndHashAlgorithms(signatureAndHashAlgorithms);
        return analysisConfig;
    }
    /* ------------------------------------ Multiple bytes ------------------------------------ */
}
