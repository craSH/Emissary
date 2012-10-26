## Emissary - A generic TCP payload proxy
This is a simple but flexible generic TCP payload proxy. The reasoning behind its creation was to have something similar to Portswigger's Burp Proxy, for TCP instead of just HTTP. Currently there is no GUI and it is just a command-line based application. Upon starting the proxy, you are presented with an IPython shell and you can manipulate various settings on the fly, such as search and replace operations, the level of information displayed, etc. Lots of work needs to be done, but it's a functional and useful tool at the moment.

The socket connections are managed by the asyncore module, and the proxy can handle truly asynchronous connections, and it seems to do so with quite good performance (I don't have any numbers at the moment - but I don't notice any performance hits when passing any interactive traffic through it such as HTTP, RDP, SSH, etc.)

Aside from some custom fuzzing and data logging code that I have not yet released, I believe IPython (>= 0.11) is the only dependency for this code to run outside of standard Python modules. The custom modules referenced are not loaded by default, so it should not be an issue. I intend the fuzzing and data logging to be modular, so you should be able to fit something in if you need to (I hope to get those components online soon as well, however.)


**Basic usage is as follows:**

    Usage: emissary.py [options]

    Options:
      -h, --help            show this help message and exit
      -l LOCAL_ADDR, --local-addr=LOCAL_ADDR
                            Local address to bind to
      -p LOCAL_PORT, --local-port=LOCAL_PORT
                            Local port to bind to
      -r REMOTE_ADDR, --remote-addr=REMOTE_ADDR
                            Remote address to bind to
      -P REMOTE_PORT, --remote-port=REMOTE_PORT
                            Remote port to bind to
      --search-request=SEARCH_REQUEST
                            String that if found will be replaced by --replace-
                            request's value
      --replace-request=REPLACE_REQUEST
                            String to replace the value of --search-request
      --search-response=SEARCH_RESPONSE
                            String that if found will be replaced by --replace-
                            request's value
      --replace-response=REPLACE_RESPONSE
                            String to replace the value of --search-request
      --regex-request       Requests: Use regular expressions for search and
                            replace instead of string constants
      --regex-response      Responses: Use regular expressions for search and
                            replace instead of string constants
      --fuzz-request        Fuzz the request which the proxy gets from the
                            connecting client             prior to sending it to
                            the remote host
      --fuzz-response       Fuzz the response which the proxy gets from the remote
                            host prior             to sending it to the conecting
                            client
      -i RUN_INFO, --run-info=RUN_INFO
                            Additional information string to add to database
                            run_info entry
      -d DEBUG, --debug=DEBUG
                            Debug level (0-5, 0: No debugging; 1: Simple
                            conneciton             information; 2: Simple data
                            information; 3: Listener data display; 4:
                            Sender data display; 5: All data display)

### Example of setting up a proxy to an SSH server (mine...)
Below you can see us setting up the proxy to listen on localhost, port 2222, and connect to the host 173.203.94.5 port 22 - the debug level is set to 4, which shows full communication from the "sender" side (the socket that connects to the server):

    $ ./emissary.py -l 127.0.0.1 -p 2222 -r 173.203.94.5 -P 22 --debug=4 

    Setting up asynch. TCP proxy with the following settings:
        Local binding Address: 127.0.0.1
        Local binding Port:    2222

        Remote host address:   173.203.94.5
        Remote host port:      22

        Debug: Level 4 (Show sender data and size of sent/received messages)

    Fuzzing <NOTHING> (Maybe you wanted --fuzz-request or --fuzz-response?)
    Listener running...

    In [1]: Connection established...
        Sender: 39 bytes read
        00000000  53 53 48 2d 32 2e 30 2d  4f 70 65 6e 53 53 48 5f   SSH-2.0- OpenSSH_
        00000010  35 2e 33 70 31 20 44 65  62 69 61 6e 2d 33 75 62   5.3p1 De bian-3ub
        00000020  75 6e 74 75 37 0d 0a                               untu7..
    Sender: 20 bytes sent
    00000000  43 6c 69 65 6e 74 2d 62  65 69 6e 67 2d 4d 69 54   Client-b eing-MiT
    00000010  4d 64 21 0a                                        Md!.
        Sender: 19 bytes read
        00000000  50 72 6f 74 6f 63 6f 6c  20 6d 69 73 6d 61 74 63   Protocol  mismatc
        00000010  68 2e 0a                                           h..
        Sender: 0 bytes read



    In [1]: 

### Simple search and replace of TCP data
You can perform simple search and replace operations via the command line, or through the IPython shell. Below, we search for "OpenSSH" in responses from the server, and replace them with "PwnedSSH":

    $ python emissary.py -l 127.0.0.1 -p 2222 -r 173.203.94.5 -P 22 --debug=4 --search-response="OpenSSH" --replace-response="PwnedSSH"

    Setting up asynch. TCP proxy with the following settings:
        Local binding Address: 127.0.0.1
        Local binding Port:    2222

        Remote host address:   173.203.94.5
        Remote host port:      22

        Debug: Level 4 (Show sender data and size of sent/received messages)

    Running string search/replace on RESPONSES with search/replace: 's/OpenSSH/PwnedSSH'
    Fuzzing <NOTHING> (Maybe you wanted --fuzz-request or --fuzz-response?)
    Listener running...

    In [1]: Connection established...
        Sender: 39 bytes read
        00000000  53 53 48 2d 32 2e 30 2d  4f 70 65 6e 53 53 48 5f   SSH-2.0- OpenSSH_
        00000010  35 2e 33 70 31 20 44 65  62 69 61 6e 2d 33 75 62   5.3p1 De bian-3ub
        00000020  75 6e 74 75 37 0d 0a                               untu7..
        Replacing literal 'OpenSSH' with 'PwnedSSH':
    Sender: 8 bytes sent
    00000000  4f 68 4e 6f 65 73 21 0a                            OhNoes!.
        Sender: 19 bytes read
        00000000  50 72 6f 74 6f 63 6f 6c  20 6d 69 73 6d 61 74 63   Protocol  mismatc
        00000010  68 2e 0a                                           h..
        Sender: 0 bytes read

This can also be done with regular expressions by adding the argument `--regex-response` - the same holds true for `--search-request` of course.

You can manipulate the search/replace functionality via the interactive shell through the local variable **sr_request** or **sr_response**, respectively. The structure of this variable is a three item array, the first being a boolean that determines if the search/replace is regular expression based or not, the second being the search term, and the third being the replacement.


The name _emissary_ was chosen because the internal name of "TcpProxy" was boring, and because it's at least a decent fit considering what the tool does.
