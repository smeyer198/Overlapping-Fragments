package de.upb.cs.message;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.OverlappingField;
import de.upb.cs.config.OverlappingFieldConfig;
import de.upb.cs.config.OverlappingOrder;
import de.upb.cs.config.OverlappingType;

import java.util.List;

public abstract class OverlappingMessageHandler {

    private final Config config;
    private final OverlappingAnalysisConfig analysisConfig;

    public OverlappingMessageHandler(Config pConfig, OverlappingAnalysisConfig analysisConfig) {
        this.config = pConfig;
        this.analysisConfig = analysisConfig;

        // Set the fields for the client messages
        config.setHighestProtocolVersion(analysisConfig.getDtlsVersion());
        config.setDefaultClientSupportedCipherSuites(analysisConfig.getSupportedCipherSuites());
        config.setDefaultClientSupportedCompressionMethods(analysisConfig.getSupportedCompressionMethods());
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(analysisConfig.getSupportedSignatureAndHashAlgorithms());
        config.setAddECPointFormatExtension(analysisConfig.isAddECPointFormatExtension());
        config.setDefaultClientSupportedPointFormats(analysisConfig.getSupportedPointFormats());
        config.setAddEllipticCurveExtension(analysisConfig.isAddEllipticCurveExtension());
        config.setDefaultClientNamedGroups(analysisConfig.getSupportedGroups());
        config.setAddRenegotiationInfoExtension(analysisConfig.isAddRenegotiationInfoExtension());

        // Set the fields for the server messages
        config.setDefaultServerSupportedCipherSuites(analysisConfig.getSelectedCipherSuite());
        config.setDefaultServerSupportedCompressionMethods(analysisConfig.getSelectedCompressionMethod());
        config.setDefaultServerSupportedSignatureAndHashAlgorithms(analysisConfig.getSelectedSignatureAndHashAlgorithm());
        config.setDefaultServerSupportedPointFormats(analysisConfig.getSelectedPointFormat());
        config.setDefaultSelectedNamedGroup(analysisConfig.getSelectedGroup());

        config.setIndividualTransportPacketsForFragments(analysisConfig.isIndividualTransportPacketsForFragments());
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
        return analysisConfig.getOverlappingBytes();
    }

    public int getAdditionalFragmentIndex() {
        return analysisConfig.getAdditionalFragmentIndex();
    }

    public abstract List<DtlsHandshakeMessageFragment> createFragmentsFromMessage(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException;
}
