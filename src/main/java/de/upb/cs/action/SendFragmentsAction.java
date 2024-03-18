package de.upb.cs.action;

import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.preparator.HandshakeMessagePreparator;
import de.rub.nds.tlsattacker.core.protocol.serializer.HandshakeMessageSerializer;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.analysis.Utils;
import de.upb.cs.message.MessageBuilder;

import java.io.IOException;
import java.util.List;

public class SendFragmentsAction extends MessageAction implements SendingAction {

    private final MessageBuilder messageBuilder;

    public SendFragmentsAction(String connectionAlias, MessageBuilder messageBuilder) {
        super(connectionAlias);

        this.messageBuilder = messageBuilder;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        // Initialize the message and update the context
        HandshakeMessage<?> handshakeMessage = messageBuilder.getHandshakeMessage();
        processMessage(handshakeMessage, tlsContext);

        try {
            List<DtlsHandshakeMessageFragment> messageFragments = messageBuilder.buildFragmentsForMessage(handshakeMessage);
            fragments.addAll(messageFragments);
            Utils.logFragments(messageBuilder.getHandshakeMessage(), messageFragments);

            send(tlsContext, messages, fragments, records, httpMessages);

            tlsContext.getDtlsFragmentLayer().increaseWriteHandshakeMessageSequence();
        } catch (OverlappingFragmentException | IOException e) {
            LOGGER.error("Error while creating or sending the fragments");
            throw new RuntimeException(e);
        }

        setExecuted(true);
    }

    public void processMessage(HandshakeMessage message, TlsContext tlsContext) {
        HandshakeMessagePreparator preparator = message.getPreparator(tlsContext);
        preparator.prepare();
        preparator.afterPrepare();

        HandshakeMessageSerializer serializer = message.getSerializer(tlsContext);
        byte[] serializedMessage = serializer.serialize();
        message.setCompleteResultingMessage(serializedMessage);

        HandshakeMessageHandler handler = message.getHandler(tlsContext);
        handler.adjustContext(message);
        handler.adjustContextAfterSerialize(message);
        handler.updateDigest(message, true);
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public List<ProtocolMessage> getSendMessages() {
        return messages;
    }

    @Override
    public List<Record> getSendRecords() {
        return records;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getSendFragments() {
        return fragments;
    }
}
