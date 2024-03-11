package de.upb.cs;

import com.beust.jcommander.JCommander;
import de.upb.cs.analysis.OverlappingFragmentException;
import de.upb.cs.config.ConnectionConfig;
import de.upb.cs.config.OverlappingAnalysisConfig;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;

import java.io.FileNotFoundException;
import java.io.FileReader;

public class Main {

    public static void main(String[] args) throws OverlappingFragmentException, JAXBException, FileNotFoundException {
        AnalysisSettings settings = new AnalysisSettings();
        JCommander.newBuilder().addObject(settings).build().parse(args);

        ConnectionConfig connectionConfig = Main.createConnectionConfig(settings);

        JAXBContext context = JAXBContext.newInstance(OverlappingAnalysisConfig.class);
        FileReader reader = new FileReader(settings.getAnalysisConfigPath());
        OverlappingAnalysisConfig analysisConfig = (OverlappingAnalysisConfig) context.createUnmarshaller().unmarshal(reader);

        OverlappingFragmentAnalysis analysis = new OverlappingFragmentAnalysis(connectionConfig, analysisConfig);
        analysis.executeAnalysis();
    }

    private static ConnectionConfig createConnectionConfig(AnalysisSettings settings) {
        ConnectionConfig connectionConfig = new ConnectionConfig();

        connectionConfig.setClientHostname(settings.getClientHostname());
        connectionConfig.setClientPort(settings.getClientPort());
        connectionConfig.setClientTimeout(settings.getClientTimeout());

        connectionConfig.setServerHostname(settings.getServerHostname());
        connectionConfig.setServerPort(settings.getServerPort());
        connectionConfig.setServerTimeout(settings.getServerTimeout());

        return connectionConfig;
    }
}
