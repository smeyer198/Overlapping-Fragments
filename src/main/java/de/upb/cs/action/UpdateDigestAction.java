package de.upb.cs.action;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.handler.HandshakeMessageHandler;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.upb.cs.analysis.DigestHandler;
import de.upb.cs.message.MessageBuilder;

import java.util.Arrays;
import java.util.List;

public class UpdateDigestAction extends ConnectionBoundAction {

    private final DigestHandler digestHandler;
    private final MessageBuilder messageBuilder;
    private final List<DtlsHandshakeMessageFragment> fragments;
    private final boolean updateDigestInContext;

    public UpdateDigestAction(String connectionAlias,
                              DigestHandler digestHandler,
                              MessageBuilder messageBuilder,
                              List<DtlsHandshakeMessageFragment> fragments,
                              boolean updateDigestInContext) {
        super(connectionAlias);

        this.digestHandler = digestHandler;
        this.messageBuilder = messageBuilder;
        this.fragments = fragments;
        this.updateDigestInContext = updateDigestInContext;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        digestHandler.updateOriginalMessageBytes(messageBuilder.getHandshakeMessage().getMessageContent().getValue());
        digestHandler.updateManipulatedMessageBytes(messageBuilder.getHandshakeMessage().getMessageContent().getValue(), fragments);

        if (updateDigestInContext) {
            updateLastDigestBytesInContext(tlsContext, digestHandler.getManipulatedMessageBytes());
        }

        setExecuted(true);
    }

    public void updateLastDigestBytesInContext(TlsContext context, byte[] updatedBytes) {
        byte[] oldDigest = context.getDigest().getRawBytes();
        byte[] digestWithoutLastBytes = Arrays.copyOfRange(oldDigest, 0, oldDigest.length - updatedBytes.length);
        byte[] newDigest = ArrayConverter.concatenate(digestWithoutLastBytes, updatedBytes);
        context.getDigest().reset();
        context.getDigest().setRawBytes(newDigest);
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
