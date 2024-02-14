package de.upb.cs.config;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;

import java.math.BigInteger;
import java.util.List;

public class OverlappingAnalysisConfig {

    private HandshakeMessageType messageType;

    private ProtocolVersion recordVersion = ProtocolVersion.DTLS12;
    private ProtocolVersion dtlsVersion = ProtocolVersion.DTLS12;

    private List<CipherSuite> supportedCipherSuites = List.of(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
    private CipherSuite selectedCipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;

    private List<CompressionMethod> supportedCompressionMethods = List.of(CompressionMethod.NULL);
    private CompressionMethod selectedCompressionMethod = CompressionMethod.NULL;

    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms = List.of(SignatureAndHashAlgorithm.RSA_SHA256);
    private SignatureAndHashAlgorithm selectedSignatureAndHashAlgorithm = SignatureAndHashAlgorithm.RSA_SHA256;

    // TODO default value
    private List<NamedGroup> supportedGroups = List.of(NamedGroup.SECP256R1);
    private NamedGroup selectedGroup = NamedGroup.SECP256R1;

    // TODO default value
    private List<ECPointFormat> supportedPointFormats = List.of(ECPointFormat.UNCOMPRESSED);
    private ECPointFormat selectedPointFormat = ECPointFormat.UNCOMPRESSED;

    private BigInteger clientDhPrivateKey = new BigInteger("FFFF", 16);
    private BigInteger clientEcPrivateKey = new BigInteger("3");
    private boolean overridePremasterSecret = false;

    private boolean addECPointFormatExtension = false;
    private boolean addEllipticCurveExtension = false;

    private boolean addRenegotiationInfoExtension = true;

    private boolean fragmentFirstCHMessage = false;

    private boolean clientAuthentication = false;

    private boolean overlappingBytesInDigest = false;

    private boolean cookieExchange = true;

    private boolean individualTransportPacketsForFragments = false;

    private final ConnectionConfig connectionConfig;

    private final OverlappingFieldConfig overlappingFieldConfig;

    public OverlappingAnalysisConfig(ConnectionConfig connectionConfig, OverlappingFieldConfig overlappingFieldConfig) {
        this.connectionConfig = connectionConfig;
        this.overlappingFieldConfig = overlappingFieldConfig;
    }

    public OverlappingField getOverlappingField() {
        return getOverlappingFieldConfig().getOverlappingField();
    }

    public OverlappingType getOverlappingType() {
        return getOverlappingFieldConfig().getOverlappingType();
    }

    public OverlappingOrder getOverlappingOrder() {
        return getOverlappingFieldConfig().getOverlappingOrder();
    }

    public int getSplitIndex() {
        return getOverlappingFieldConfig().getSplitIndex();
    }

    public byte[] getOverlappingBytes() {
        return getOverlappingFieldConfig().getOverlappingBytes();
    }

    public int getAdditionalFragmentIndex() {
        return getOverlappingFieldConfig().getAdditionalFragmentIndex();
    }

    public HandshakeMessageType getMessageType() {
        return messageType;
    }

    public void setMessageType(HandshakeMessageType messageType) {
        this.messageType = messageType;
    }

    public ProtocolVersion getRecordVersion() {
        return recordVersion;
    }

    public void setRecordVersion(ProtocolVersion recordVersion) {
        this.recordVersion = recordVersion;
    }

    public ProtocolVersion getDtlsVersion() {
        return dtlsVersion;
    }

    public void setDtlsVersion(ProtocolVersion dtlsVersion) {
        this.dtlsVersion = dtlsVersion;
    }

    public List<CipherSuite> getSupportedCipherSuites() {
        return supportedCipherSuites;
    }

    public void setSupportedCipherSuites(List<CipherSuite> supportedCipherSuites) {
        this.supportedCipherSuites = supportedCipherSuites;
    }

    public CipherSuite getSelectedCipherSuite() {
        return selectedCipherSuite;
    }

    public void setSelectedCipherSuite(CipherSuite selectedCipherSuite) {
        this.selectedCipherSuite = selectedCipherSuite;
    }

    public List<CompressionMethod> getSupportedCompressionMethods() {
        return supportedCompressionMethods;
    }

    public void setSupportedCompressionMethods(List<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public CompressionMethod getSelectedCompressionMethod() {
        return selectedCompressionMethod;
    }

    public void setSelectedCompressionMethod(CompressionMethod selectedCompressionMethod) {
        this.selectedCompressionMethod = selectedCompressionMethod;
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
        return supportedSignatureAndHashAlgorithms;
    }

    public void setSupportedSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
        this.supportedSignatureAndHashAlgorithms = supportedSignatureAndHashAlgorithms;
    }

    public SignatureAndHashAlgorithm getSelectedSignatureAndHashAlgorithm() {
        return selectedSignatureAndHashAlgorithm;
    }

    public void setSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm selectedSignatureAndHashAlgorithm) {
        this.selectedSignatureAndHashAlgorithm = selectedSignatureAndHashAlgorithm;
    }

    public List<NamedGroup> getSupportedGroups() {
        return supportedGroups;
    }

    public void setSupportedGroups(List<NamedGroup> supportedGroups) {
        this.supportedGroups = supportedGroups;
    }

    public NamedGroup getSelectedGroup() {
        return selectedGroup;
    }

    public void setSelectedGroup(NamedGroup selectedGroup) {
        this.selectedGroup = selectedGroup;
    }

    public List<ECPointFormat> getSupportedPointFormats() {
        return supportedPointFormats;
    }

    public void setSupportedPointFormats(List<ECPointFormat> supportedPointFormats) {
        this.supportedPointFormats = supportedPointFormats;
    }

    public ECPointFormat getSelectedPointFormat() {
        return selectedPointFormat;
    }

    public void setSelectedPointFormat(ECPointFormat selectedPointFormat) {
        this.selectedPointFormat = selectedPointFormat;
    }

    public boolean isAddECPointFormatExtension() {
        return addECPointFormatExtension;
    }

    public void setAddECPointFormatExtension(boolean addECPointFormatExtension) {
        this.addECPointFormatExtension = addECPointFormatExtension;
    }

    public boolean isAddEllipticCurveExtension() {
        return addEllipticCurveExtension;
    }

    public void setAddEllipticCurveExtension(boolean addEllipticCurveExtension) {
        this.addEllipticCurveExtension = addEllipticCurveExtension;
    }

    public boolean isAddRenegotiationInfoExtension() {
        return addRenegotiationInfoExtension;
    }

    public void setAddRenegotiationInfoExtension(boolean addRenegotiationInfoExtension) {
        this.addRenegotiationInfoExtension = addRenegotiationInfoExtension;
    }

    public boolean isFragmentFirstCHMessage() {
        return fragmentFirstCHMessage;
    }

    public void setFragmentFirstCHMessage(boolean fragmentFirstCHMessage) {
        this.fragmentFirstCHMessage = fragmentFirstCHMessage;
    }

    public boolean isClientAuthentication() {
        return clientAuthentication;
    }

    public void setClientAuthentication(boolean clientAuthentication) {
        this.clientAuthentication = clientAuthentication;
    }

    public boolean isOverlappingBytesInDigest() {
        return overlappingBytesInDigest;
    }

    public void setOverlappingBytesInDigest(boolean overlappingBytesInDigest) {
        this.overlappingBytesInDigest = overlappingBytesInDigest;
    }

    public boolean isCookieExchange() {
        return cookieExchange;
    }

    public void setCookieExchange(boolean cookieExchange) {
        this.cookieExchange = cookieExchange;
    }

    public ConnectionConfig getConnectionConfig() {
        return connectionConfig;
    }

    public OverlappingFieldConfig getOverlappingFieldConfig() {
        return overlappingFieldConfig;
    }

    public boolean isIndividualTransportPacketsForFragments() {
        return individualTransportPacketsForFragments;
    }

    public void setIndividualTransportPacketsForFragments(boolean individualTransportPacketsForFragments) {
        this.individualTransportPacketsForFragments = individualTransportPacketsForFragments;
    }

    public BigInteger getClientDhPrivateKey() {
        return clientDhPrivateKey;
    }

    public void setClientDhPrivateKey(BigInteger clientDhPrivateKey) {
        this.clientDhPrivateKey = clientDhPrivateKey;
    }

    public BigInteger getClientEcPrivateKey() {
        return clientEcPrivateKey;
    }

    public void setClientEcPrivateKey(BigInteger clientEcPrivateKey) {
        this.clientEcPrivateKey = clientEcPrivateKey;
    }

    public boolean isOverridePremasterSecret() {
        return overridePremasterSecret;
    }

    public void setOverridePremasterSecret(boolean overridePremasterSecret) {
        this.overridePremasterSecret = overridePremasterSecret;
    }
}
