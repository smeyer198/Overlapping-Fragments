package de.upb.cs.message;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.AnalysisConfig;
import de.upb.cs.config.Constants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

public abstract class MessageBuilder {

    protected static final Logger LOGGER = LoggerFactory.getLogger(MessageBuilder.class);

    protected final AnalysisConfig analysisConfig;
    protected final TlsContext context;
    protected final FragmentBuilder fragmentBuilder;
    private HandshakeMessage<?> handshakeMessage;

    public MessageBuilder(AnalysisConfig analysisConfig, TlsContext context) {
        this.analysisConfig = analysisConfig;
        this.context = context;
        this.fragmentBuilder = new FragmentBuilder();
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

    public HandshakeMessage<?> getHandshakeMessage() {
        return handshakeMessage;
    }

    protected void setHandshakeMessage(HandshakeMessage<?> handshakeMessage) {
        this.handshakeMessage = handshakeMessage;
    }

    public int getWriteMessageSequence() {
        return context.getDtlsFragmentLayer().getWriteHandshakeMessageSequence();
    }

    public abstract List<DtlsHandshakeMessageFragment> buildFragmentsForMessage(HandshakeMessage<?> message) throws OverlappingFragmentException;
}
