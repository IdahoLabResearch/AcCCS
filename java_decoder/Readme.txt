To run the java EXI decoder, execute it in a seperate terminal (or process) with the following command:

$ java -jar V2Gdecoder-jar-with-dependencies.jar -w

The -w option has the service run as a web service on TCP port 9000.  The decoding is then done by sending a POST request with the binary and returned as XML text.

Or, if you choose to just decode one message at a time, you can run it:

$ java -jar V2Gdecoder-jar-with-dependencies.jar -e -s 809a021050908c0c0c0c0d11f0

To properly decode the EXI, you need to run the java decoder with the correct schema files in the schema directory.  The java app expects these files in the schema directory of the parent directory from where it was run.  To process DIN SPEC communications, use schema_din.  To process ISO 15118, use schema_15118.
