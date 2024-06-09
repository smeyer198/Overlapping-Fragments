package de.upb.cs;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.upb.cs.analysis.AbstractAnalysis;
import de.upb.cs.analysis.OverlappingFragmentException;
import jakarta.xml.bind.JAXBException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;

public class Main {

    private static final Logger LOGGER = LoggerFactory.getLogger(OverlappingFragmentAnalysis.class);

    public static void main(String[] args) throws OverlappingFragmentException, JAXBException, FileNotFoundException {
        AnalysisSettings settings = new AnalysisSettings();
        JCommander.newBuilder().addObject(settings).build().parse(args);

        LOGGER.info("Setup analysis...");
        AbstractAnalysis analysis = OverlappingFragmentAnalysis.getOverlappingFragmentAnalysis(settings.getHostname(), settings.getPort(), settings.getTimeout(), settings.getAnalysisConfigPath());
        analysis.initializeWorkflowTrace();
        LOGGER.info("Analysis setup done");

        LOGGER.info("Starting analysis...");
        State state = analysis.getState();
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DTLS, state);
        workflowExecutor.executeWorkflow();
        LOGGER.info("Analysis finished");

        analysis.analyzeResults();
    }

}
