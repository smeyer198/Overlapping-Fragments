package de.upb.cs.analysis;

import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.crypto.MessageDigestCollector;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HelloVerifyRequestMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.upb.cs.action.SendFragmentsAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

public class DigestHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(DigestHandler.class);
    private byte[] originalMessageBytes;
    private byte[] manipulatedMessageBytes;

    public DigestHandler() {
        originalMessageBytes = new byte[]{};
        manipulatedMessageBytes = new byte[]{};
    }

    public void updateOriginalMessageBytes(byte[] messageBytes) {
        originalMessageBytes = Arrays.copyOf(messageBytes, messageBytes.length);
    }

    public void updateManipulatedMessageBytes(byte[] messageBytes, List<DtlsHandshakeMessageFragment> fragments) {
        manipulatedMessageBytes = Arrays.copyOf(messageBytes, messageBytes.length);

        for (DtlsHandshakeMessageFragment fragment : fragments) {
            int offset = fragment.getOffsetConfig();
            byte[] fragmentContent = fragment.getFragmentContentConfig();
            byte[] originalFragmentContent = Arrays.copyOfRange(manipulatedMessageBytes, offset, offset + fragmentContent.length);

            // Overwrite the original content with the manipulated fragment content
            if (!Arrays.equals(originalFragmentContent, fragmentContent)) {
                StringBuilder sb = new StringBuilder("Overwriting original bytes with overlapping bytes in digest:\n");
                for (int i = 0; i < fragmentContent.length; i++) {
                    int dataIndex = offset + i;

                    if (messageBytes[dataIndex] != fragmentContent[i]) {
                        sb.append("\t")
                                .append(Utils.bytesToHexString(new byte[]{manipulatedMessageBytes[dataIndex]}))
                                .append("-> ")
                                .append(Utils.bytesToHexString(new byte[]{fragmentContent[i]})).append(", ");
                        manipulatedMessageBytes[dataIndex] = fragmentContent[i];
                    }
                }
                //LOGGER.info(sb.toString());
            }
        }
        LOGGER.info("Manipulated fragment:\n\t{}", Utils.bytesToHexString(manipulatedMessageBytes));
    }

    public byte[] getManipulatedMessageBytes() {
        return manipulatedMessageBytes;
    }

    public MessageDigestCollector parseWorkflowTraceForClientFinished(WorkflowTrace trace, TlsContext context, HandshakeMessageType messageType, boolean useManipulatedMessageBytes) {
        int writeHandshakeMessageSequence = 0;
        int readHandshakeMessageSequence = 0;
        MessageDigestCollector digestCollector = new MessageDigestCollector();

        for (TlsAction action : trace.getTlsActions()) {
            if (!action.executedAsPlanned()) {
                continue;
            }

            if (!(action instanceof MessageAction)) {
                continue;
            }
            MessageAction messageAction = (MessageAction) action;

            if (messageAction instanceof SendFragmentsAction) {
                byte[] messageContent;
                if (useManipulatedMessageBytes) {
                    messageContent = manipulatedMessageBytes;
                } else {
                    messageContent = originalMessageBytes;
                }

                byte[] completeMessage;
                if (messageAction.isSendingAction()) {
                    completeMessage = wrapInSingleFragment(messageType, messageContent, writeHandshakeMessageSequence, context);
                    writeHandshakeMessageSequence++;
                } else if (messageAction.isReceivingAction()) {
                    completeMessage = wrapInSingleFragment(messageType, messageContent, readHandshakeMessageSequence, context);
                    readHandshakeMessageSequence++;
                } else {
                    LOGGER.error("Action {} is not a SendingAction or ReceivingAction", action.toCompactString());
                    continue;
                }

                digestCollector.append(completeMessage);
                continue;
            }

            for (ProtocolMessage<?> message : messageAction.getMessages()) {
                // Skip ChangeCipherSpec
                if (!message.isHandshakeMessage()) {
                    continue;
                }

                HandshakeMessage<?> handshakeMessage = (HandshakeMessage<?>) message;

                // Finished messages are not part of ClientFinished MAC computation
                if (message instanceof FinishedMessage) {
                    return digestCollector;
                }

                byte[] messageContent;
                /*if (handshakeMessage.getHandshakeMessageType() == messageType && useManipulatedMessageBytes) {
                    messageContent = manipulatedMessageBytes;
                } else {*/
                    messageContent = handshakeMessage.getSerializer(context).serializeHandshakeMessageContent();
                //}

                byte[] completeMessage;
                if (messageAction.isSendingAction()) {
                    completeMessage = wrapInSingleFragment(handshakeMessage.getHandshakeMessageType(), messageContent, writeHandshakeMessageSequence, context);
                    writeHandshakeMessageSequence++;
                } else if (messageAction.isReceivingAction()) {
                    completeMessage = wrapInSingleFragment(handshakeMessage.getHandshakeMessageType(), messageContent, readHandshakeMessageSequence, context);
                    readHandshakeMessageSequence++;
                } else {
                    LOGGER.error("Action {} is not a SendingAction or ReceivingAction", action.toCompactString());
                    continue;
                }

                digestCollector.append(completeMessage);

                if (handshakeMessage instanceof HelloVerifyRequestMessage) {
                    digestCollector.reset();
                }
            }
        }

        return digestCollector;
    }

    public MessageDigestCollector parseWorkflowTraceForServerFinished(WorkflowTrace trace, TlsContext context, HandshakeMessageType messageType, boolean useManipulatedMessageBytes) {
        int writeHandshakeMessageSequence = 0;
        int readHandshakeMessageSequence = 0;
        MessageDigestCollector digestCollector = new MessageDigestCollector();

        for (TlsAction action : trace.getTlsActions()) {
            if (!action.executedAsPlanned()) {
                continue;
            }

            if (!(action instanceof MessageAction)) {
                continue;
            }
            MessageAction messageAction = (MessageAction) action;

            if (messageAction instanceof SendFragmentsAction) {
                byte[] messageContent;
                if (useManipulatedMessageBytes) {
                    messageContent = manipulatedMessageBytes;
                } else {
                    messageContent = originalMessageBytes;
                }

                byte[] completeMessage;
                //if (messageAction.isSendingAction()) {
                    completeMessage = wrapInSingleFragment(messageType, messageContent, writeHandshakeMessageSequence, context);
                    writeHandshakeMessageSequence++;
                /*} else if (messageAction.isReceivingAction()) {
                    completeMessage = wrapInSingleFragment(messageType, messageContent, readHandshakeMessageSequence, context);
                    readHandshakeMessageSequence++;
                } else {
                    LOGGER.error("Action {} is not a SendingAction or ReceivingAction", action.toCompactString());
                    continue;
                }*/

                digestCollector.append(completeMessage);
                continue;
            }

            for (ProtocolMessage<?> message : messageAction.getMessages()) {
                // Skip ChangeCipherSpec
                if (!message.isHandshakeMessage()) {
                    continue;
                }

                HandshakeMessage<?> handshakeMessage = (HandshakeMessage<?>) message;

                // Server Finished message is not part of the MAC computation
                if (messageAction.isReceivingAction() && handshakeMessage instanceof FinishedMessage) {
                    continue;
                }

                byte[] messageContent;
                /*if (handshakeMessage.getHandshakeMessageType() == messageType && useManipulatedMessageBytes) {
                    messageContent = manipulatedMessageBytes;
                } else {*/
                    messageContent = handshakeMessage.getSerializer(context).serializeHandshakeMessageContent();
                //}

                byte[] completeMessage;
                if (messageAction.isSendingAction()) {
                    completeMessage = wrapInSingleFragment(handshakeMessage.getHandshakeMessageType(), messageContent, writeHandshakeMessageSequence, context);
                    writeHandshakeMessageSequence++;
                } else if (messageAction.isReceivingAction()) {
                    completeMessage = wrapInSingleFragment(handshakeMessage.getHandshakeMessageType(), messageContent, readHandshakeMessageSequence, context);
                    readHandshakeMessageSequence++;
                } else {
                    LOGGER.error("Action {} is not a SendingAction or ReceivingAction", action.toCompactString());
                    continue;
                }

                digestCollector.append(completeMessage);

                if (handshakeMessage instanceof HelloVerifyRequestMessage) {
                    digestCollector.reset();
                }
            }
        }
        return digestCollector;
    }

    // See https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/layer/impl/DtlsFragmentLayer.java
    private byte[] wrapInSingleFragment(HandshakeMessageType messageType, byte[] messageContent, int messageSequence, TlsContext context) {
        DtlsHandshakeMessageFragment fragment = new DtlsHandshakeMessageFragment();
        fragment.setHandshakeMessageTypeConfig(messageType);
        fragment.setHandshakeMessageLengthConfig(messageContent.length);
        fragment.setMessageSequenceConfig(messageSequence);
        fragment.setOffsetConfig(0);
        fragment.setFragmentContentConfig(messageContent);

        fragment.getPreparator(context).prepare();
        return fragment.getSerializer(context).serialize();
    }
}
