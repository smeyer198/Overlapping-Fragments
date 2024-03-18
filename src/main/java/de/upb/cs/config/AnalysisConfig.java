package de.upb.cs.config;

import de.rub.nds.tlsattacker.core.config.Config;
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
import java.util.List;

@XmlRootElement(name = "AnalysisConfig")
@XmlAccessorType(XmlAccessType.NONE)
public class AnalysisConfig {

    @XmlElement(name = "tlsAttackerConfig")
    private final Config tlsAttackerConfig;

    @XmlElementWrapper(name = "fragments")
    @XmlElement(name = "fragment")
    private List<FragmentConfig> fragments = new ArrayList<>();

    @XmlElement(name = "message")
    private MessageType messageType = MessageType.NONE;

    @XmlElement(name = "dhPrivateKey")
    private String dhPrivateKey = "FFFF";

    @XmlElement(name = "ecPrivateKey")
    private String ecPrivateKey = "3";

    @XmlElement(name = "useUpdatedKeys")
    private boolean useUpdatedKeys = false;

    @XmlElement(name = "clientAuthentication")
    private boolean clientAuthentication = false;

    @XmlElement(name = "overlappingBytesInDigest")
    private boolean overlappingBytesInDigest = false;

    @XmlElement(name = "cookieExchange")
    private boolean cookieExchange = true;

    @XmlElement(name = "certificatePath", defaultValue = "")
    private String certificatePath = "";

    @XmlElement(name = "certificateKeyPath", defaultValue = "")
    private String certificateKeyPath = "";

    /** Relevant for version in ServerHello */
    @XmlElement(name = "updateProtocolVersion")
    private ProtocolVersion updateProtocolVersion = null;

    /** Relevant for cipher suite in ServerHello */
    @XmlElement(name = "updateCipherSuite")
    private CipherSuite updateCipherSuite = null;

    @XmlTransient
    private HandshakeMessageType handshakeMessageType;

    public AnalysisConfig() {
        tlsAttackerConfig = new Config();

        tlsAttackerConfig.setHighestProtocolVersion(ProtocolVersion.DTLS12);
        tlsAttackerConfig.setDefaultClientSupportedCipherSuites(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        tlsAttackerConfig.setAddSignatureAndHashAlgorithmsExtension(true);
        tlsAttackerConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(SignatureAndHashAlgorithm.RSA_SHA256);
        tlsAttackerConfig.setAddEllipticCurveExtension(false);
        tlsAttackerConfig.setDefaultClientNamedGroups(NamedGroup.SECP256R1);
        tlsAttackerConfig.setAddECPointFormatExtension(false);
        tlsAttackerConfig.setDefaultClientSupportedPointFormats(ECPointFormat.UNCOMPRESSED);

        tlsAttackerConfig.setDefaultSelectedProtocolVersion(ProtocolVersion.DTLS12);
        tlsAttackerConfig.setDefaultSelectedCipherSuite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        tlsAttackerConfig.setDefaultSelectedSignatureAndHashAlgorithm(SignatureAndHashAlgorithm.RSA_SHA256);
        tlsAttackerConfig.setDefaultSelectedNamedGroup(NamedGroup.SECP256R1);
        tlsAttackerConfig.setDefaultSelectedPointFormat(ECPointFormat.UNCOMPRESSED);
        tlsAttackerConfig.setEnforceSettings(true);
    }

    public Config getTlsAttackerConfig() {
        return tlsAttackerConfig;
    }

    public List<FragmentConfig> getFragments() {
        return fragments;
    }

    public void setFragments(List<FragmentConfig> fragments) {
        this.fragments = fragments;
    }

    public MessageType getMessageType() {
        return messageType;
    }

    public void setMessageType(MessageType messageType) {
        this.messageType = messageType;
    }

    public HandshakeMessageType getHandshakeMessageType() {
        return handshakeMessageType;
    }

    public void setHandshakeMessageType(HandshakeMessageType handshakeMessageType) {
        this.handshakeMessageType = handshakeMessageType;
    }

    @XmlElement(name = "clientHelloVersion")
    public ProtocolVersion getClientHelloVersion() {
        return tlsAttackerConfig.getHighestProtocolVersion();
    }

    public void setClientHelloVersion(ProtocolVersion clientHelloVersion) {
        tlsAttackerConfig.setHighestProtocolVersion(clientHelloVersion);
    }

    @XmlElement(name = "serverHelloVersion")
    public ProtocolVersion getServerHelloVersion() {
        return tlsAttackerConfig.getDefaultSelectedProtocolVersion();
    }

    public void setServerHelloVersion(ProtocolVersion serverHelloVersion) {
        tlsAttackerConfig.setDefaultSelectedProtocolVersion(serverHelloVersion);
    }

    @XmlElementWrapper(name = "clientHelloCipherSuites")
    @XmlElement(name = "cipherSuite")
    public List<CipherSuite> getClientHelloCipherSuites() {
        return tlsAttackerConfig.getDefaultClientSupportedCipherSuites();
    }

    public void setClientHelloCipherSuites(List<CipherSuite> clientHelloCipherSuites) {
        tlsAttackerConfig.setDefaultClientSupportedCipherSuites(clientHelloCipherSuites);
    }

    @XmlElement(name = "serverHelloCipherSuite")
    public CipherSuite getServerHelloCipherSuite() {
        return tlsAttackerConfig.getDefaultSelectedCipherSuite();
    }

    public void setServerHelloCipherSuite(CipherSuite serverHelloCipherSuite) {
        tlsAttackerConfig.setDefaultSelectedCipherSuite(serverHelloCipherSuite);
    }

    @XmlElementWrapper(name = "clientHelloSignatureAndHashAlgorithms")
    @XmlElement(name = "signatureAndHashAlgorithm")
    public List<SignatureAndHashAlgorithm> getClientHelloSignatureAndHashAlgorithms() {
        return tlsAttackerConfig.getDefaultClientSupportedSignatureAndHashAlgorithms();
    }

    public void setClientHelloSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> clientHelloSignatureAndHashAlgorithms) {
        tlsAttackerConfig.setDefaultClientSupportedSignatureAndHashAlgorithms(clientHelloSignatureAndHashAlgorithms);
    }

    @XmlElement(name = "serverHelloSignatureAndHashAlgorithm")
    public SignatureAndHashAlgorithm getServerHelloSignatureAndHashAlgorithm() {
        return tlsAttackerConfig.getDefaultSelectedSignatureAndHashAlgorithm();
    }

    public void setServerHelloSignatureAndHashAlgorithm(SignatureAndHashAlgorithm serverHelloSignatureAndHashAlgorithm) {
        tlsAttackerConfig.setDefaultSelectedSignatureAndHashAlgorithm(serverHelloSignatureAndHashAlgorithm);
    }

    @XmlElement(name = "addEllipticCurveExtension")
    public boolean isAddEllipticCurveExtension() {
        return tlsAttackerConfig.isAddEllipticCurveExtension();
    }

    public void setAddEllipticCurveExtension(boolean addEllipticCurveExtension) {
        tlsAttackerConfig.setAddEllipticCurveExtension(addEllipticCurveExtension);
    }

    @XmlElementWrapper(name = "clientHelloGroups")
    @XmlElement(name = "group")
    public List<NamedGroup> getClientHelloGroups() {
        return tlsAttackerConfig.getDefaultClientNamedGroups();
    }

    public void setClientHelloGroups(List<NamedGroup> clientHelloGroups) {
        tlsAttackerConfig.setDefaultClientNamedGroups(clientHelloGroups);
    }

    @XmlElement(name = "serverHelloGroup")
    public NamedGroup getServerHelloGroup() {
        return tlsAttackerConfig.getDefaultSelectedNamedGroup();
    }

    public void setServerHelloGroup(NamedGroup serverHelloGroup) {
        tlsAttackerConfig.setDefaultSelectedNamedGroup(serverHelloGroup);
    }

    @XmlElementWrapper(name = "clientHelloPointFormats")
    @XmlElement(name = "pointFormat")
    public List<ECPointFormat> getClientHelloPointFormats() {
        return tlsAttackerConfig.getDefaultClientSupportedPointFormats();
    }

    public void setClientHelloPointFormats(List<ECPointFormat> clientHelloPointFormats) {
        tlsAttackerConfig.setDefaultClientSupportedPointFormats(clientHelloPointFormats);
    }

    @XmlElement(name = "addECPointFormatExtension")
    public boolean isAddECPointFormatExtension() {
        return tlsAttackerConfig.isAddECPointFormatExtension();
    }

    public void setAddECPointFormatExtension(boolean addECPointFormatExtension) {
        tlsAttackerConfig.setAddECPointFormatExtension(addECPointFormatExtension);
    }

    @XmlElement(name = "serverHelloPointFormat")
    public ECPointFormat getServerHelloPointFormat() {
        return tlsAttackerConfig.getDefaultSelectedPointFormat();
    }

    public void setServerHelloPointFormat(ECPointFormat serverHelloPointFormat) {
        tlsAttackerConfig.setDefaultSelectedPointFormat(serverHelloPointFormat);
    }

    @XmlElement(name = "useIndividualDatagrams")
    public boolean isUseIndividualDatagrams() {
        return tlsAttackerConfig.isIndividualTransportPacketsForFragments();
    }

    public void setUseIndividualDatagrams(boolean useIndividualDatagrams) {
        tlsAttackerConfig.setIndividualTransportPacketsForFragments(useIndividualDatagrams);
    }

    @XmlElement(name = "addRenegotiationInfoExtension")
    public boolean isAddRenegotiationInfoExtension() {
        return tlsAttackerConfig.isAddRenegotiationInfoExtension();
    }

    public void setAddRenegotiationInfoExtension(boolean addRenegotiationInfoExtension) {
        tlsAttackerConfig.setAddRenegotiationInfoExtension(addRenegotiationInfoExtension);
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
