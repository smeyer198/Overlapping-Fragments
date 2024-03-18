package de.upb.cs.action;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.upb.cs.message.ClientKeyExchangeBuilder;

public class ComputeDynamicClientKeyExchangeAction extends ConnectionBoundAction {

    private final ClientKeyExchangeBuilder clientKeyExchangeBuilder;

    public ComputeDynamicClientKeyExchangeAction(String connectionAlias, ClientKeyExchangeBuilder clientKeyExchangeBuilder) {
        super(connectionAlias);

        this.clientKeyExchangeBuilder = clientKeyExchangeBuilder;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        ClientKeyExchangeMessage<?> clientKeyExchangeMessage =
                new WorkflowConfigurationFactory(state.getConfig())
                        .createClientKeyExchangeMessage(
                                AlgorithmResolver.getKeyExchangeAlgorithm(
                                        tlsContext.getChooser().getSelectedCipherSuite()));

        clientKeyExchangeBuilder.setClientKeyExchangeMessage(clientKeyExchangeMessage);
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
