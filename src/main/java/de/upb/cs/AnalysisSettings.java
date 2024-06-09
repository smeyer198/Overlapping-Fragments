package de.upb.cs;

import com.beust.jcommander.Parameter;

public class AnalysisSettings {

    @Parameter(names = {"-hostname"}, description = "Client or Server Hostname")
    private String hostname = "localhost";

    @Parameter(names = {"-port"}, description = "Client or Server Port")
    private int port = 4433;

    @Parameter(names = {"-timeout"}, description = "Client or Server Timeout")
    private int timeout = 2000;

    @Parameter(names = {"-analysisConfig"}, description = "Path to the analysis config")
    private String analysisConfigPath = "";

    public String getHostname() {
        return hostname;
    }

    public int getPort() {
        return port;
    }

    public int getTimeout() {
        return timeout;
    }

    public String getAnalysisConfigPath() {
        return analysisConfigPath;
    }
}
