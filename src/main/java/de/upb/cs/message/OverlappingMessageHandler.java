package de.upb.cs.message;

import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.certificate.PemUtil;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;
import de.upb.cs.util.LogUtils;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.List;

public abstract class OverlappingMessageHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(OverlappingFieldConfig.class);

    private final Config config;
    private final OverlappingAnalysisConfig analysisConfig;

    public OverlappingMessageHandler(Config pConfig, OverlappingAnalysisConfig analysisConfig) {
        this.config = pConfig;
        this.analysisConfig = analysisConfig;

        // Set the fields for the client messages
        // config.setDefaultHighestClientProtocolVersion(analysisConfig.getDtlsVersion());
        config.setHighestProtocolVersion(analysisConfig.getClientHelloVersion());
        config.setDefaultClientSupportedCipherSuites(analysisConfig.getClientHelloCipherSuites());
        config.setDefaultClientSupportedCompressionMethods(CompressionMethod.NULL);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(analysisConfig.getClientHelloSignatureAndHashAlgorithms());
        config.setAddECPointFormatExtension(analysisConfig.isAddECPointFormatExtension());
        config.setDefaultClientSupportedPointFormats(analysisConfig.getClientHelloPointFormats());
        config.setAddEllipticCurveExtension(analysisConfig.isAddEllipticCurveExtension());
        config.setDefaultClientNamedGroups(analysisConfig.getClientHelloGroups());
        config.setAddRenegotiationInfoExtension(analysisConfig.isAddRenegotiationInfoExtension());

        CertificateKeyPair keyPair = loadCertificate();
        if (keyPair != null) {
            config.setDefaultExplicitCertificateKeyPair(keyPair);
            config.setAutoSelectCertificate(false);
        }

        // Set the fields for the server messages
        config.setDefaultSelectedProtocolVersion(analysisConfig.getServerHelloVersion());
        config.setDefaultServerSupportedCipherSuites(analysisConfig.getServerHelloCipherSuite());
        config.setDefaultServerSupportedCompressionMethods(CompressionMethod.NULL);
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(analysisConfig.getServerHelloSignatureAndHashAlgorithm());
        config.setDefaultServerSupportedPointFormats(analysisConfig.getServerHelloPointFormat());
        config.setDefaultSelectedNamedGroup(analysisConfig.getServerHelloGroup());

        config.setIndividualTransportPacketsForFragments(analysisConfig.isIndividualTransportPacketsForFragments());
    }

    private CertificateKeyPair loadCertificate() {
        if (analysisConfig.getCertificatePath().isEmpty() && analysisConfig.getCertificateKeyPath().isEmpty()) {
            LOGGER.debug("Using certificate from TLS-Attacker");
            return null;
        }

        try {
            Security.addProvider(new BouncyCastleProvider());

            Certificate certificate = PemUtil.readCertificate(new File(analysisConfig.getCertificatePath()));
            PrivateKey key = PemUtil.readPrivateKey(new File(analysisConfig.getCertificateKeyPath()));

            return new CertificateKeyPair(certificate, key);
        } catch (CertificateException | IOException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public Config getConfig() {
        return config;
    }

    public OverlappingAnalysisConfig getAnalysisConfig() {
        return analysisConfig;
    }

    public OverlappingFieldConfig getOverlappingFieldConfig() {
        return analysisConfig.getOverlappingFieldConfig();
    }

    public OverlappingField getOverlappingField() {
        return analysisConfig.getOverlappingField();
    }

    public OverlappingType getOverlappingType() {
        return analysisConfig.getOverlappingType();
    }

    public OverlappingOrder getOverlappingOrder() {
        return analysisConfig.getOverlappingOrder();
    }

    public int getSplitIndex() {
        return analysisConfig.getSplitIndex();
    }

    public byte[] getOverlappingBytes() {
        return LogUtils.hexToByteArray(analysisConfig.getOverlappingBytes());
    }

    public int getAdditionalFragmentIndex() {
        return analysisConfig.getAdditionalFragmentIndex();
    }

    public abstract List<DtlsHandshakeMessageFragment> createFragmentsFromMessage(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException;
}
