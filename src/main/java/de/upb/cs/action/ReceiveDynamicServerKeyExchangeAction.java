package de.upb.cs.action;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * See https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/workflow/action/SendDynamicServerKeyExchangeAction.java
 */
public class ReceiveDynamicServerKeyExchangeAction extends MessageAction implements ReceivingAction {

    public ReceiveDynamicServerKeyExchangeAction(String connectionAlias) {
        super(connectionAlias);

        messages = new ArrayList<>();
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(connectionAlias).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        CipherSuite selectedCipherSuite = tlsContext.getChooser().getSelectedCipherSuite();
        ServerKeyExchangeMessage<?> serverKeyExchangeMessage =
                new WorkflowConfigurationFactory(state.getConfig())
                        .createServerKeyExchangeMessage(
                                AlgorithmResolver.getKeyExchangeAlgorithm(selectedCipherSuite));

        if (serverKeyExchangeMessage != null) {
            messages.add(serverKeyExchangeMessage);
            receive(tlsContext, messages, fragments, records, httpMessages);
        } else {
            LOGGER.debug("Skipping DynamicServerKeyExchangeAction as it is not required or dynamic selection failed.");
        }
        setExecuted(true);
    }

    @Override
    public void reset() {
        messages = new ArrayList<>();
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public List<ProtocolMessage> getReceivedMessages() {
        return messages;
    }

    @Override
    public List<Record> getReceivedRecords() {
        return records;
    }

    @Override
    public List<DtlsHandshakeMessageFragment> getReceivedFragments() {
        return fragments;
    }

    @Override
    public List<HttpMessage> getReceivedHttpMessages() {
        return httpMessages;
    }

    @Override
    public List<ProtocolMessageType> getGoingToReceiveProtocolMessageTypes() {
        return new ArrayList<>(List.of(ProtocolMessageType.HANDSHAKE));
    }

    @Override
    public List<HandshakeMessageType> getGoingToReceiveHandshakeMessageTypes() {
        return new ArrayList<>(List.of(HandshakeMessageType.SERVER_KEY_EXCHANGE));
    }

    @Override
    public String toString() {
        StringBuilder sb;
        if (isExecuted()) {
            sb = new StringBuilder("Receive Dynamic Server Key Exchange Action:\n");

            if (messages.isEmpty()) {
                sb.append("\tReceived no ServerKeyExchange message\n");
            } else {
                sb.append("\t");
                for (ProtocolMessage<?> message : messages) {
                    sb.append(message.toCompactString());
                    sb.append(",");
                }
                sb.append("\n");
            }
        } else {
            sb = new StringBuilder("Receive Dynamic Server Key Exchange Action: (not executed)\n");
        }
        return sb.toString();
    }
}
