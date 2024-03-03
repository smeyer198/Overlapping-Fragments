package de.upb.cs.config;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@XmlRootElement(name = "AnalysisConfig")
@XmlAccessorType(XmlAccessType.FIELD)
public class OverlappingAnalysisConfig {

    @XmlTransient
    private HandshakeMessageType messageType;

    private ProtocolVersion clientHelloVersion = ProtocolVersion.DTLS12;
    private ProtocolVersion serverHelloVersion = ProtocolVersion.DTLS12;

    @XmlElementWrapper(name = "clientHelloCipherSuites")
    @XmlElement(name = "cipherSuite")
    private List<CipherSuite> clientHelloCipherSuites;
    private CipherSuite serverHelloCipherSuite = CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA;

    @XmlElementWrapper(name = "clientHelloSignatureAndHashAlgorithms")
    @XmlElement(name = "signatureAndHashAlgorithm")
    private List<SignatureAndHashAlgorithm> clientHelloSignatureAndHashAlgorithms;
    private SignatureAndHashAlgorithm serverHelloSignatureAndHashAlgorithm = SignatureAndHashAlgorithm.RSA_SHA256;

    @XmlElementWrapper(name = "clientHelloGroups")
    @XmlElement(name = "group")
    private List<NamedGroup> clientHelloGroups;
    private NamedGroup serverHelloGroup = NamedGroup.SECP256R1;

    @XmlElementWrapper(name = "clientHelloPointFormats")
    @XmlElement(name = "pointFormat")
    private List<ECPointFormat> clientHelloPointFormats;
    private ECPointFormat serverHelloPointFormat = ECPointFormat.UNCOMPRESSED;

    @XmlElement(name = "dhPrivateKey", defaultValue = "FFFF")
    private String dhPrivateKey = "FFFF";

    @XmlElement(name = "ecPrivateKey", defaultValue = "3")
    private String ecPrivateKey = "3";

    private boolean useUpdatedKeys = false;

    private boolean addECPointFormatExtension = false;
    private boolean addEllipticCurveExtension = false;

    private boolean addRenegotiationInfoExtension = true;

    private boolean fragmentFirstCHMessage = false;

    private boolean clientAuthentication = false;

    private boolean overlappingBytesInDigest = false;

    private boolean cookieExchange = true;

    private boolean individualTransportPacketsForFragments = true;

    @XmlElement(name = "certificatePath", defaultValue = "")
    private String certificatePath = "";

    @XmlElement(name = "certificateKeyPath", defaultValue = "")
    private String certificateKeyPath = "";

    /** Relevant for version in ServerHello */
    private ProtocolVersion updateProtocolVersion = null;

    /** Relevant for cipher suite in ServerHello */
    private CipherSuite updateCipherSuite = null;

    @XmlElement(name = "FieldConfig", required = true)
    private OverlappingFieldConfig overlappingFieldConfig;

    private OverlappingAnalysisConfig() {
        clientHelloCipherSuites = new ArrayList<>(List.of(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA));
        clientHelloSignatureAndHashAlgorithms = new ArrayList<>(List.of(SignatureAndHashAlgorithm.RSA_SHA256));
        clientHelloGroups = new ArrayList<>(List.of(NamedGroup.SECP256R1));
        clientHelloPointFormats = new ArrayList<>(List.of(ECPointFormat.UNCOMPRESSED));
    }

    public OverlappingAnalysisConfig(OverlappingFieldConfig overlappingFieldConfig) {
        this();
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

    public String getOverlappingBytes() {
        return overlappingFieldConfig.getOverlappingBytes();
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

    public ProtocolVersion getClientHelloVersion() {
        return clientHelloVersion;
    }

    public void setClientHelloVersion(ProtocolVersion clientHelloVersion) {
        this.clientHelloVersion = clientHelloVersion;
    }

    public ProtocolVersion getServerHelloVersion() {
        return serverHelloVersion;
    }

    public void setServerHelloVersion(ProtocolVersion serverHelloVersion) {
        this.serverHelloVersion = serverHelloVersion;
    }

    public List<CipherSuite> getClientHelloCipherSuites() {
        return clientHelloCipherSuites;
    }

    public void setClientHelloCipherSuites(List<CipherSuite> clientHelloCipherSuites) {
        this.clientHelloCipherSuites = clientHelloCipherSuites;
    }

    public CipherSuite getServerHelloCipherSuite() {
        return serverHelloCipherSuite;
    }

    public void setServerHelloCipherSuite(CipherSuite serverHelloCipherSuite) {
        this.serverHelloCipherSuite = serverHelloCipherSuite;
    }

    public List<SignatureAndHashAlgorithm> getClientHelloSignatureAndHashAlgorithms() {
        return clientHelloSignatureAndHashAlgorithms;
    }

    public void setClientHelloSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> clientHelloSignatureAndHashAlgorithms) {
        this.clientHelloSignatureAndHashAlgorithms = clientHelloSignatureAndHashAlgorithms;
    }

    public SignatureAndHashAlgorithm getServerHelloSignatureAndHashAlgorithm() {
        return serverHelloSignatureAndHashAlgorithm;
    }

    public void setServerHelloSignatureAndHashAlgorithm(SignatureAndHashAlgorithm serverHelloSignatureAndHashAlgorithm) {
        this.serverHelloSignatureAndHashAlgorithm = serverHelloSignatureAndHashAlgorithm;
    }

    public List<NamedGroup> getClientHelloGroups() {
        return clientHelloGroups;
    }

    public void setClientHelloGroups(List<NamedGroup> clientHelloGroups) {
        this.clientHelloGroups = clientHelloGroups;
    }

    public NamedGroup getServerHelloGroup() {
        return serverHelloGroup;
    }

    public void setServerHelloGroup(NamedGroup serverHelloGroup) {
        this.serverHelloGroup = serverHelloGroup;
    }

    public List<ECPointFormat> getClientHelloPointFormats() {
        return clientHelloPointFormats;
    }

    public void setClientHelloPointFormats(List<ECPointFormat> clientHelloPointFormats) {
        this.clientHelloPointFormats = clientHelloPointFormats;
    }

    public ECPointFormat getServerHelloPointFormat() {
        return serverHelloPointFormat;
    }

    public void setServerHelloPointFormat(ECPointFormat serverHelloPointFormat) {
        this.serverHelloPointFormat = serverHelloPointFormat;
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

    public OverlappingFieldConfig getOverlappingFieldConfig() {
        return overlappingFieldConfig;
    }

    public boolean isIndividualTransportPacketsForFragments() {
        return individualTransportPacketsForFragments;
    }

    public void setIndividualTransportPacketsForFragments(boolean individualTransportPacketsForFragments) {
        this.individualTransportPacketsForFragments = individualTransportPacketsForFragments;
    }

    public String getDhPrivateKey() {
        return dhPrivateKey;
    }

    public void setDhPrivateKey(String dhPrivateKey) {
        this.dhPrivateKey = dhPrivateKey;
    }

    public String getEcPrivateKey() {
        return ecPrivateKey;
    }

    public void setEcPrivateKey(String ecPrivateKey) {
        this.ecPrivateKey = ecPrivateKey;
    }

    public boolean isUseUpdatedKeys() {
        return useUpdatedKeys;
    }

    public void setUseUpdatedKeys(boolean useUpdatedKeys) {
        this.useUpdatedKeys = useUpdatedKeys;
    }

    public CipherSuite getUpdateCipherSuite() {
        return updateCipherSuite;
    }

    public void setUpdateCipherSuite(CipherSuite updateCipherSuite) {
        this.updateCipherSuite = updateCipherSuite;
    }

    public ProtocolVersion getUpdateProtocolVersion() {
        return updateProtocolVersion;
    }

    public void setUpdateProtocolVersion(ProtocolVersion updateProtocolVersion) {
        this.updateProtocolVersion = updateProtocolVersion;
    }

    public String getCertificatePath() {
        return certificatePath;
    }

    public void setCertificatePath(String certificatePath) {
        this.certificatePath = certificatePath;
    }

    public String getCertificateKeyPath() {
        return certificateKeyPath;
    }

    public void setCertificateKeyPath(String certificateKeyPath) {
        this.certificateKeyPath = certificateKeyPath;
    }
}
