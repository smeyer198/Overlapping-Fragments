package de.upb.cs.message;

import de.rub.nds.tlsattacker.core.certificate.CertificateKeyPair;
import de.rub.nds.tlsattacker.core.certificate.PemUtil;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.Constants;
import de.upb.cs.config.OverlappingAnalysisConfig;
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

public abstract class MessageBuilder {

    protected static final Logger LOGGER = LoggerFactory.getLogger(MessageBuilder.class);

    protected final OverlappingAnalysisConfig analysisConfig;
    protected final TlsContext context;
    protected final FragmentBuilder fragmentBuilder;

    public MessageBuilder(OverlappingAnalysisConfig analysisConfig, TlsContext context) {
        this.analysisConfig = analysisConfig;
        this.context = context;
        this.fragmentBuilder = new FragmentBuilder();

        Config config = analysisConfig.getTlsAttackerConfig();

        CertificateKeyPair keyPair = loadCertificate();
        if (keyPair != null) {
            config.setDefaultExplicitCertificateKeyPair(keyPair);
            config.setAutoSelectCertificate(false);
        }
    }

    public int parseOffset(int offset, int messageLength) {
        if (offset < 0) {
            return messageLength + offset;
        }
        return offset;
    }

    public int parseLength(int length, int offset, int messageLength) {
        if (length == Constants.DEFAULT_LENGTH) {
            return length;
        }

        if (length < 0) {
            return messageLength - offset + length;
        }
        return length;
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

    public abstract List<DtlsHandshakeMessageFragment> buildFragmentsForMessage(DtlsHandshakeMessageFragment originalFragment) throws OverlappingFragmentException;
}
