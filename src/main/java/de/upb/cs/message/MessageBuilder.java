package de.upb.cs.message;

import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.HandshakeMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
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

    public void prepareMessage(HandshakeMessage message) {
        if (message instanceof ClientHelloMessage || message instanceof ClientKeyExchangeMessage) {
            context.getChooser().getContext().setTalkingConnectionEndType(ConnectionEndType.CLIENT);
        }
        HandshakeMessagePreparator preparator = message.getPreparator(context);
        preparator.prepare();
        preparator.afterPrepare();

        HandshakeMessageSerializer serializer = message.getSerializer(context);
        byte[] serializedMessage = serializer.serialize();
        message.setCompleteResultingMessage(serializedMessage);
    }

    public void adjustContext(HandshakeMessage message) {
        HandshakeMessageHandler handler = message.getHandler(context);
        handler.adjustContext(message);
        handler.adjustContextAfterSerialize(message);
    }

    public abstract List<DtlsHandshakeMessageFragment> buildFragmentsForMessage() throws OverlappingFragmentException;
}
