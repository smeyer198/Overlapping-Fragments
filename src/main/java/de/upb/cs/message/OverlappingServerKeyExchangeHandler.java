package de.upb.cs.message;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.layer.context.TlsContext;
import de.rub.nds.tlsattacker.core.protocol.message.DtlsHandshakeMessageFragment;
import de.upb.cs.config.OverlappingAnalysisConfig;
import de.upb.cs.analysis.OverlappingFragmentException;

import java.util.List;

public class OverlappingServerKeyExchangeHandler extends OverlappingMessageHandler {

    public OverlappingServerKeyExchangeHandler(Config config, OverlappingAnalysisConfig analysisConfig) {
        super(config, analysisConfig);
    }

    @Override
    public List<DtlsHandshakeMessageFragment> createFragmentsFromMessage(DtlsHandshakeMessageFragment originalFragment, TlsContext context) throws OverlappingFragmentException {
        switch (getOverlappingField()) {
            case CLIENT_KEY_EXCHANGE_DH:

            case SERVER_KEY_EXCHANGE_ECDH:

            default:
                throw new OverlappingFragmentException("Field " + getOverlappingField() + " is not allowed in ServerKeyExchange message");
        }
    }
}
