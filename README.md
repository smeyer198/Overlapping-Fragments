# Overlapping Fragment Analysis

Program to perform DTLS handshakes and arbitrarily fragment messages. The program can be installed with `mvn clean install`.

### Run programmatically
Include the project as dependency:
```
<dependency>
    <groupId>de.upb.cs</groupId>
    <artifactId>OverlappingFragments</artifactId>
    <version>1.0.0</version>
</dependency>
```

Initialze an `AnalysisConfig`:
```
AnalysisConfig config = new AnalyisConfig();
config.setMessage(MessageType.CLIENT_HELLO);

config.setClientHelloCipherSuites(Arrays.asList(
    CipherSuites.TLS_RSA_WITH_AES_256_CBC_SHA,
    CipherSuites.TLS_RSA_WITH_AES_128_CBC_SHA));

// First fragment that ends after the first cipher suite
FragmentConfig fragment1 = new FragmentConfig();
fragment1.setOffset(0);
fragment1.setLengthConfig(new LengthConfig(2, Field.CIPHER_SUITES));

// Second fragment that starts after the first cipher suite
FragmentConfig fragment2 = new FragmentConfig();
fragment2.setOffsetConfig(new OffsetConfig(2, FIELD.CIPHER_SUITES));
fragment2.setPrependBytes("2F");    // Prepend injected bytes

config.setFragments(Arrays.asList(fragment1, fragment2));
```
Run the program:
```
// Initialize the program based on an AnalysisConfig
AbstractAnalysis analysis = OverlappingFragmentAnalysis.getAnalysis("127.0.0.1", 4433, analysisConfig);

// Prepare the state for TLS-Attacker
analysis.initializeWorkflowTrace();

// Execute the handshake using TLS-Attacker
State state = analysis.getState();
DtlsWorkflowExecutor executor = new DtlsWorkflowExecutor(state);
executor.executeWorkflow();

// Extract the results
AnalysisResults results = analysis.getResults();
```

### Run from the command line:
After installation with Maven, you can run the program with the jar file in the `target` directory.
`java -cp OverlappingFragments.jar de.upb.cs.Main -hostname 127.0.0.1 -port 8090 -analysisConfig ./example_config.xml` 
The `example_config.xml` can look like this:
```XML
<?xml version="1.0" encoding="UTF-8"?>
<AnalysisConfig>
    <message>CLIENT_HELLO</message>
    <fragments>
        <!-- First fragment -->
        <fragment>
            <offset>0</offset>
            <lengthConfig>
                <length>2</length>
                <field>CIPHER_SUITES</field>
            </lengthConfig>
        </fragment>
        <!-- Second fragment -->
        <fragment>
            <offsetConfig>
                <offset>2</offset>
                <field>CIPHER_SUITES</field>
            </offsetConfig>
            <prependBytes>2f</prependBytes>
        </fragment>
    </fragments>

    <clientHelloCipherSuites>
        <cipherSuite>TLS_RSA_WITH_AES_256_CBC_SHA</cipherSuite>
        <cipherSuite>TLS_RSA_WITH_AES_128_CBC_SHA</cipherSuite>
    </clientHelloCipherSuites>

    <overlappingBytesInDigest>false</overlappingBytesInDigest>
</AnalysisConfig>
```

# Logs
Running the program against DTLS servers (e.g. OpenSSL), the program logs the handshake and the results:
```
[main] INFO de.upb.cs.OverlappingFragmentAnalysis - Setup analysis...
[main] INFO de.upb.cs.OverlappingFragmentAnalysis - Analysis setup done
[main] INFO de.upb.cs.OverlappingFragmentAnalysis - Starting analysis...
[main] INFO de.upb.cs.analysis.Utils -
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Message: CLIENT_HELLO
        Original message:  FE FD FE 96 CB 99 60 B4 20 BB 38 51 D9 D4 7A CB 93 3D BE 70 39 9B F6 C9 2D A3 3A F0 1D 4F B7 70 E9 8C 00 14 0B 97 2C 7B 11 0C B1 AF 3D 35 05 53 80 4F 06 D8 CB F5 1E CD 00 04 00 35 00 2F 01 00 00 0D 00 0D 00 04 00 02 04 01 FF 01 00 01 00
        Fragment 1:        FE FD FE 96 CB 99 60 B4 20 BB 38 51 D9 D4 7A CB 93 3D BE 70 39 9B F6 C9 2D A3 3A F0 1D 4F B7 70 E9 8C 00 14 0B 97 2C 7B 11 0C B1 AF 3D 35 05 53 80 4F 06 D8 CB F5 1E CD 00 04 00 35
        Fragment 2:                                                                                                                                                                                         2F 00 2F 01 00 00 0D 00 0D 00 04 00 02 04 01 FF 01 00 01 00
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[main] INFO de.upb.cs.OverlappingFragmentAnalysis - Analysis finished
[main] INFO de.upb.cs.analysis.ResultsHandler - Executed actions:
Send Action:
        Messages:CLIENT_HELLO,

Receive Action:
        Expected:HELLO_VERIFY_REQUEST,
        Actual:HELLO_VERIFY_REQUEST,

de.upb.cs.action.SendFragmentsAction@af12f4b8
de.upb.cs.action.UpdateDigestAction@af12f4b8
Receive Action:
        Expected:SERVER_HELLO,
        Actual:SERVER_HELLO,

Receive Action:
        Expected:CERTIFICATE,
        Actual:CERTIFICATE,

Receive Dynamic Server Key Exchange Action:
        Received no ServerKeyExchange message

Receive Action:
        Expected:SERVER_HELLO_DONE,
        Actual:SERVER_HELLO_DONE,

Send Dynamic Client Key Exchange Action:
        Messages:RSA_CLIENT_KEY_EXCHANGE,

Send Action:
        Messages:CHANGE_CIPHER_SPEC,

Send Action:
        Messages:FINISHED,

Receive Action:
        Expected:CHANGE_CIPHER_SPEC,
        Actual:CHANGE_CIPHER_SPEC,

Receive Action:
        Expected:FINISHED,
        Actual:FINISHED,

[main] INFO de.upb.cs.analysis.ResultsHandler - Handshake parameters:
        Proposed DTLS version: DTLS12
        Selected DTLS version: DTLS12
        Proposed Cipher Suite: [TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA]
        Selected Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA
        Proposed SignatureAndHashAlgorithms: [RSA_SHA256]
        Selected SignatureAndHashAlgorithm: RSA_SHA256

[main] INFO de.upb.cs.analysis.ResultsHandler - VerifyData:
        Finished:    96 6D 66 82 A9 1C 25 50 FB AF 38 B6
        Original:    FD 86 89 3D 81 47 C2 C5 4E F6 89 54
        Manipulated: 96 6D 66 82 A9 1C 25 50 FB AF 38 B6

[main] INFO de.upb.cs.analysis.ResultsHandler - ClientFinished contained manipulated bytes, Server interpreted manipulated bytes
```
The injected byte `2F` is part of the second sent fragment. OpenSSL interpreted this byte because it selected the cipher suite `TLS_RSA_WITH_AES_128_CBC_SHA` and accepted the Finished message computed over the injected byte (overlappingBytesInDigest = true). Comparing the Verify Data value, the server's value is equal to the value that results when computing the Verify Data over the injected byte (Manipulated) and not the original message byte.
