package de.upb.cs.action;

import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.PRFAlgorithm;
import de.rub.nds.tlsattacker.core.exceptions.ActionExecutionException;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.action.ConnectionBoundAction;
import de.rub.nds.tlsattacker.core.workflow.chooser.Chooser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AdvancedChangeCipherSuiteAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LoggerFactory.getLogger(AdvancedChangeCipherSuiteAction.class);
    public CipherSuite oldValue;
    private final CipherSuite newValue;

    public AdvancedChangeCipherSuiteAction(String alias, CipherSuite newValue) {
        super(alias);

        this.oldValue = null;
        this.newValue = newValue;
    }

    @Override
    public void execute(State state) throws ActionExecutionException {
        TlsContext tlsContext = state.getContext(getConnectionAlias()).getTlsContext();

        if (isExecuted()) {
            throw new ActionExecutionException("Action already executed!");
        }

        oldValue = tlsContext.getSelectedCipherSuite();
        tlsContext.setSelectedCipherSuite(newValue);
        LOGGER.debug("Set Cipher Suite to {}" , newValue);

        adjustPRF(state.getTlsContext());
        setExecuted(true);
    }

    public void adjustPRF(TlsContext context) {
        // Same as https://github.com/tls-attacker/TLS-Attacker/blob/main/TLS-Core/src/main/java/de/rub/nds/tlsattacker/core/protocol/handler/ServerHelloHandler.java#L161
        Chooser chooser = context.getChooser();

        if (!chooser.getSelectedProtocolVersion().isSSL()) {
            PRFAlgorithm algorithm = AlgorithmResolver.getPRFAlgorithm(chooser.getSelectedProtocolVersion(), chooser.getSelectedCipherSuite());
            context.setPrfAlgorithm(algorithm);
            LOGGER.info("Update PRF algorithm to {}", algorithm);
        }
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    @Override
    public void reset() {
        setExecuted(false);
    }

    @Override
    public String toString() {
        return "AdvancedChangeCipherSuiteAction:\n\tChanged Cipher Suite: " + oldValue + " -> " + newValue + "\n";
    }
}
