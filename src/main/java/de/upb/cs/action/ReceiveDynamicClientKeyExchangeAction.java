package de.upb.cs.action;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.http.HttpMessage;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.MessageAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * See https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/workflow/action/SendDynamicClientKeyExchangeAction.java
 */
public class ReceiveDynamicClientKeyExchangeAction extends MessageAction implements ReceivingAction {

    public ReceiveDynamicClientKeyExchangeAction(String connectionAlias) {
        super(connectionAlias);

        messages = new ArrayList<>();
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(connectionAlias).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        ClientKeyExchangeMessage clientKeyExchangeMessage =
                new WorkflowConfigurationFactory(state.getConfig())
                        .createClientKeyExchangeMessage(
                                AlgorithmResolver.getKeyExchangeAlgorithm(
                                        tlsContext.getChooser().getSelectedCipherSuite()));

        if (clientKeyExchangeMessage != null) {
            messages.add(clientKeyExchangeMessage);
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
        return new ArrayList<>(List.of(HandshakeMessageType.CLIENT_KEY_EXCHANGE));
    }

    @Override
    public String toString() {
        StringBuilder sb;
        if (isExecuted()) {
            sb = new StringBuilder("Receive Dynamic Client Key Exchange Action:\n");

            if (messages.isEmpty()) {
                sb.append("\tReceived no ClientKeyExchange message\n");
            } else {
                for (ProtocolMessage message : messages) {
                    sb.append(message.toCompactString());
                    sb.append(",");
                }
            }
        } else {
            sb = new StringBuilder("Receive Dynamic Client Key Exchange Action: (not executed)\n");
        }
        return sb.toString();
    }
}
