package de.upb.cs.action;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ServerKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.upb.cs.message.ServerKeyExchangeBuilder;

public class ComputeDynamicServerKeyExchangeAction extends ConnectionBoundAction {

    private final ServerKeyExchangeBuilder serverKeyExchangeBuilder;

    public ComputeDynamicServerKeyExchangeAction(String connectionAlias, ServerKeyExchangeBuilder serverKeyExchangeBuilder) {
        super(connectionAlias);

        this.serverKeyExchangeBuilder = serverKeyExchangeBuilder;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        CipherSuite selectedCipherSuite = tlsContext.getChooser().getSelectedCipherSuite();
        ServerKeyExchangeMessage<?> serverKeyExchangeMessage =
                new WorkflowConfigurationFactory(state.getConfig())
                        .createServerKeyExchangeMessage(
                                AlgorithmResolver.getKeyExchangeAlgorithm(selectedCipherSuite));

        serverKeyExchangeBuilder.setServerKeyExchangeMessage(serverKeyExchangeMessage);
        setExecuted(true);
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
