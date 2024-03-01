package de.upb.cs;

import com.beust.jcommander.Parameter;

public class AnalysisSettings {

    @Parameter(names = {"-client_hostname"}, description = "Client hostname")
    private String clientHostname = "localhost";

    @Parameter(names = {"-server_hostname"}, description = "Server hostname")
    private String serverHostname = "localhost";

    @Parameter(names = {"-client_port"}, description = "Client port")
    private int clientPort = 4433;

    @Parameter(names = {"-server_port"}, description = "Server port")
    private int serverPort = 4433;

    @Parameter(names = {"-client_timeout"}, description = "Client timeout")
    private int clientTimeout = 2000;

    @Parameter(names = {"-server_timeout"}, description = "Server timeout")
    private int serverTimeout = 10000;

    @Parameter(names = {"-analysisConfig"}, description = "Path to the analysis config")
    private String analysisConfigPath = "./";


    public String getClientHostname() {
        return clientHostname;
    }

    public String getServerHostname() {
        return serverHostname;
    }

    public int getClientPort() {
        return clientPort;
    }

    public int getServerPort() {
        return serverPort;
    }

    public int getClientTimeout() {
        return clientTimeout;
    }

    public int getServerTimeout() {
        return serverTimeout;
    }

    public String getAnalysisConfigPath() {
        return analysisConfigPath;
    }
}
