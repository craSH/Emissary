#!/usr/bin/env python

# Shall we log our session? (Requires postgresql and such setup)
logging_enabled = False
fuzzing_enabled = False

dump_width = 90

# This will enable logging data to a PostgreSQL database, enter at your own risk.
# This should be replaced with a better, generic logging system. TODO.
if logging_enabled:
    from fuzzLogger import *

# This currently relies on some private fuzzing code - things should be changed
# to use a more generic fuzzing system. TODO.
if fuzzing_enabled:
    sys.path.append('../fuzzerCore')
    import datafuzzer

# Global imports
import sys, os, re, socket, asyncore
from threading import Thread

# Local imports
from terminal import TerminalController
from http_helper import *
from utils import hexdump, indent

class forwarder(asyncore.dispatcher):
    def __init__(self, ip, port, remoteip,remoteport,backlog=5):
        asyncore.dispatcher.__init__(self)
        self.remoteip=remoteip
        self.remoteport=remoteport
        self.create_socket(socket.AF_INET,socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((ip,port))
        self.listen(backlog)
        if fuzzing_enabled:
            self.fuzzer = datafuzzer.DataFuzzer()
        else:
            self.fuzzer = None

    def handle_accept(self):
        conn, addr = self.accept()

        if(debug > 0):
            print(term.render('${BOLD}Connection established...${NORMAL}'))

        # share a single logdata object between sender and reciever
        # so that logdata is always populated with a request AND response
        # if fuzz_request and fuzz_response both True, will clobber non fuzzed data
        if logging_enabled:
            logdata = logData()
        else:
            logdata = None
        sender(receiver(conn, self.fuzzer, logdata), self.remoteip,self.remoteport, self.fuzzer, logdata)

class receiver(asyncore.dispatcher):
    def __init__(self, conn, fuzzer, logdata):
        asyncore.dispatcher.__init__(self,conn)
        self.from_remote_buffer=''
        self.to_remote_buffer=''
        self.sender=None
        self.fuzzer = fuzzer
        self.logdata = logdata

    def handle_connect(self):
        pass

    def handle_read(self):
        read = self.recv(4096)
        debug_str = ""
        if(debug == 1 or debug == 3 or debug == 5):
            debug_str += term.render('    ${CYAN}Listener: %i bytes read:${NORMAL}\n') % len(read)
        if(debug == 3 or debug >= 5):
            debug_str += hexdump(read, indent=True)
        if debug_str:
            if debug >= 5:
                debug_str = indent(debug_str, dump_width)
            print(debug_str)

        self.from_remote_buffer += read


    def writable(self):
        return (len(self.to_remote_buffer) > 0)

    def handle_write(self):
        # This conditional stuff could really stand to be cleaned up
        sent = ""
        modified_data = self.to_remote_buffer
        found_gzip = False
        headers = ''

        # De-gzip HTTP responses
        #if http_is_gzip(modified_data):
        #    found_gzip = True

        if found_gzip:
            print(term.render('${YELLOW}GZIP HTTP Response! Uncompressing...${NORMAL}'))

            headers, compressed_body = http_split(modified_data)
            # FIXME: Setting modified_data to the http body here ensures that headers will not be altered below - this may be undesirable!
            modified_data = http_gunzip(compressed_body)

        # Perform search/replace as appropriate
        if sr_response:
            # Check if regex
            if sr_response[0]:
                if len(re.findall(sr_response[1], modified_data)) > 0:
                    modified_data = re.sub(sr_response[1], sr_response[2], modified_data)
                    debug_str = term.render("${YELLOW}Listener: Replacing regex %s with %s:${NORMAL}" % (repr(sr_response[1]), repr(sr_response[2])))
                    if debug >= 5:
                        debug_str = indent(debug_str, dump_width)
                    print(debug_str)
            else:
                if sr_response[1] in modified_data:
                    modified_data = modified_data.replace(sr_response[1], sr_response[2])
                    debug_str = term.render("${YELLOW}Listener: Replacing literal %s with %s:${NORMAL}" % (repr(sr_response[1]), repr(sr_response[2])))
                    if debug >= 5:
                        debug_str = indent(debug_str, dump_width)
                    print(debug_str)

        # Check if we want to fuzz the request or not
        if(fuzz_response):
            modified_data = self.fuzzer.fuzz(modified_data)

        # Reconstruct HTTP gzip message if we were dealing with compressed data
        if found_gzip:
            print(term.render('${YELLOW}Constructing compressed GZIP HTTP Response!${NORMAL}'))
            compressed_modified_data = http_gzip(modified_data)
            # Fixup the Content-Length header
            compressed_len = len(compressed_modified_data)
            headers = re.sub('(Content-Length\s*:[^\d]*)(\d+)', '\\1 %d' % compressed_len, headers)

            modified_data = http_reconstruct_message(headers, compressed_modified_data)

        # Send the (potentially) modified response data onward
        sent = self.send(modified_data)

        # Store RESPONSE and time of response for logging
        # Msg received from the server (i.e. SMTP response "220 OK")
        if self.logdata:
            self.logdata.response_data += modified_data
            if(not self.logdata.response_time):
                self.logdata.response_time = postgres_datetime_ms()


        debug_str = ""
        if(debug == 1 or debug == 3 or debug == 5):
            debug_str += term.render('${RED}Listener: %i bytes sent:${NORMAL}\n') % sent
        if(debug == 3 or debug >= 5):
            debug_str += hexdump(modified_data, indent=False)
        if debug_str:
            if debug >= 5:
                debug_str = indent(debug_str, dump_width)
            print(debug_str)

        self.to_remote_buffer = self.to_remote_buffer[sent:]

    def handle_close(self):
        self.close()
        if self.sender:
            self.sender.close()
        if(debug > 0):
            print(term.render('${BOLD}Connection closed...${NORMAL}'))
        # commit logdata to database and remove so it doesnt get logged twice (in other close)
        if self.logdata:
            #logger.log_iteration_data(self.logdata)
            self.logdata = None

class sender(asyncore.dispatcher):
    def __init__(self, receiver, remoteaddr, remoteport, fuzzer, logdata):
        asyncore.dispatcher.__init__(self)
        self.receiver=receiver
        receiver.sender=self
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((remoteaddr, remoteport))
        self.fuzzer = fuzzer
        self.logdata = logdata

    def handle_connect(self):
        pass

    def handle_read(self):
        read = self.recv(4096)
        if(debug == 1 or debug == 4 or debug == 5):
            print(term.render('    ${BOLD}${CYAN}Sender: %i bytes read:${NORMAL}') % len(read))
        if(debug == 4 or debug >= 5):
            print hexdump(read, indent=True)

        self.receiver.to_remote_buffer += read

    def writable(self):
        return (len(self.receiver.from_remote_buffer) > 0)

    def handle_write(self):
        # This conditional stuff could really stand to be cleaned up
        sent = ""
        modified_data = self.receiver.from_remote_buffer

        # Perform search/replace as appropriate
        if sr_request:
            # Check if regex
            if sr_request[0]:
                if len(re.findall(sr_request[1], self.receiver.from_remote_buffer)) > 0:
                    modified_data = re.sub(sr_request[1], sr_request[2], self.receiver.from_remote_buffer)
                    print(term.render("${YELLOW}Sender: Replacing regex %s with %s:${NORMAL}" % (repr(sr_request[1]), repr(sr_request[2]))))
            else:
                if sr_request[1] in self.receiver.from_remote_buffer:
                    modified_data = self.receiver.from_remote_buffer.replace(sr_request[1], sr_request[2])
                    print(term.render("${YELLOW}Sender: Replacing literal %s with %s:${NORMAL}" % (repr(sr_request[1]), repr(sr_request[2]))))

        # Check if we want to fuzz the request or not
        if(fuzz_request):
            modified_data = self.fuzzer.mutate(modified_data)

        sent = self.send(modified_data)

        # Store REQUEST and time of request for logging
        # Msg received from the server (i.e. SMTP request "EHLO foobar.com")
        if self.logdata:
            self.logdata.request_data += modified_data
            if(not self.logdata.request_time):
                self.logdata.request_time = postgres_datetime_ms()

        if(debug == 1 or debug == 4 or debug == 5):
            print(term.render('${BOLD}${RED}Sender: %i bytes sent:${NORMAL}') % sent)
        if(debug == 4 or debug >= 5):
            print hexdump(modified_data, indent=False)
        self.receiver.from_remote_buffer = self.receiver.from_remote_buffer[sent:]

    def handle_close(self):
        self.close()
        self.receiver.close()
        # commit logdata to database and remove so it doesnt get logged twice (in other close)
        if self.logdata:
            #logger.log_iteration_data(self.logdata)
            self.logdata = None


def main():
    import optparse
    parser = optparse.OptionParser()
    # Shall we fuzz the request, response, or both?
    # Set via optparse in main
    global sr_request   # search/replace tuple for requests - (True, [search, replace]) where true means to use regex
    global sr_response  # search/replace tuple for responses - (True, [search, replace]) where true means to use regex
    global fuzz_request
    global fuzz_response

    # Other module-wide variables
    global debug
    global term
    global logger
    global fwdr

    parser.add_option( '-l','--local-addr', dest='local_addr',default='127.0.0.1', help='Local address to bind to')
    parser.add_option( '-p','--local-port', type='int',dest='local_port',default=1234, help='Local port to bind to')
    parser.add_option( '-r','--remote-addr',dest='remote_addr', help='Remote address to bind to')
    parser.add_option( '-P','--remote-port', type='int',dest='remote_port',default=80, help='Remote port to bind to')

    parser.add_option( '--search-request', dest='search_request',default='', help='String that if found will be replaced by --replace-request\'s value')
    parser.add_option( '--replace-request', dest='replace_request',default='', help='String to replace the value of --search-request')
    parser.add_option( '--search-response', dest='search_response',default='', help='String that if found will be replaced by --replace-request\'s value')
    parser.add_option( '--replace-response', dest='replace_response',default='', help='String to replace the value of --search-request')

    parser.add_option( '--regex-request', action='store_true' ,dest='request_use_regex', help='Requests: Use regular expressions for search and replace instead of string constants')
    parser.add_option( '--regex-response', action='store_true' ,dest='response_use_regex', help='Responses: Use regular expressions for search and replace instead of string constants')

    parser.add_option( '--fuzz-request', action='store_true' ,dest='fuzz_request', help='Fuzz the request which the proxy gets from the connecting client \
            prior to sending it to the remote host')
    parser.add_option( '--fuzz-response', action='store_true' ,dest='fuzz_response', help='Fuzz the response which the proxy gets from the remote host prior \
            to sending it to the conecting client')

    parser.add_option( '-i','--run-info', dest='run_info',default='', help='Additional information string to add to database run_info entry')

    parser.add_option( '-d','--debug', type='int',dest='debug',default=0, help='Debug level (0-5, 0: No debugging; 1: Simple conneciton \
            information; 2: Simple data information; 3: Listener data display; 4: \
            Sender data display; 5: All data display)')

    (options, args) = parser.parse_args()

    if not options.remote_addr or not options.remote_port:
        parser.print_help()
        exit(1)

    # Validate options for search/replace
    if (options.search_request and not options.replace_request) or (options.replace_request and not options.search_request):
        print >>sys.stderr, "Both --search-request and --replace-request must be provided together"
        exit(1)

    if (options.search_response and not options.replace_response) or (options.replace_response and not options.search_response):
        print >>sys.stderr, "Both --search-response and --replace-response must be provided together"
        exit(1)

    # Setup a TerminalController for formatted output
    term = TerminalController()

    # Print the current run information
    print(term.render("""\nSetting up asynch. TCP proxy with the following settings:
    ${GREEN}Local binding Address: %s
    Local binding Port:    %s${NORMAL}

    ${RED}Remote host address:   %s
    Remote host port:      %s${NORMAL}
    """) % (options.local_addr, options.local_port, options.remote_addr, options.remote_port))

    # Set the debug value
    debug = options.debug

    # If run info was passed in on the command line, use that for the run_info table
    # additional info field (It will have what's being fuzzed prepended to it as well)
    run_additional_info = options.run_info

    # Print the selected debug value
    if(debug > 0):
        if(debug == 1):
            print("    Debug: Level 1 (Show simple connection information)")
        elif(debug == 2):
            print("    Debug: Level 2 (Show simple data information, such as the size of sent/received messages)")
        elif(debug == 3):
            print("    Debug: Level 3 (Show listener data and size of sent/received messages)")
        elif(debug == 4):
            print("    Debug: Level 4 (Show sender data and size of sent/received messages)")
        elif(debug == 5):
            print("    Debug: Level 5 (Show all possible information, including the size of sent/received messages, and their data for listener and sender)")
    print("")

    # Display and setup search/replace things
    if options.search_request and options.replace_request:
        sr_request = [None, options.search_request.decode('string-escape'), options.replace_request.decode('string-escape')]
        # Check if we want to use regex instead of string constants
        if options.request_use_regex:
            # Use regex instead of string replace
            print(term.render("Running regex search/replace on ${BOLD}REQUESTS${NORMAL} with regex: 's/%s/%s'" % (sr_request[1], sr_request[2])))
            sr_request[0] = True
        else:
            print(term.render("Running string search/replace on ${BOLD}REQUESTS${NORMAL} with search/replace: 's/%s/%s'" % (sr_request[1], sr_request[2])))
            sr_request[0] = False
    else:
        sr_request = None

    if options.search_response and options.replace_response:
        sr_response = [None, options.search_response.decode('string-escape'), options.replace_response.decode('string-escape')]
        # Check if we want to use regex instead of string constants
        if options.response_use_regex:
            print(term.render("Running regex search/replace on ${BOLD}RESPONSES${NORMAL} with regex: 's/%s/%s'" % (sr_response[1], sr_response[2])))
            sr_response[0] = True
        else:
            print(term.render("Running string search/replace on ${BOLD}RESPONSES${NORMAL} with search/replace: 's/%s/%s'" % (sr_response[1], sr_response[2])))
            sr_response[0] = False
    else:
        sr_response = None

    # Setup which to fuzz - request, response, neither, both?
    if(options.fuzz_request):
        fuzz_request = options.fuzz_request
        run_additional_info = "Fuzzing REQUESTS; " + run_additional_info
        print(term.render("Fuzzing ${BOLD}REQUESTS${NORMAL}"))
    else:
        fuzz_request = False

    if(options.fuzz_response):
        fuzz_response = options.fuzz_response
        run_additional_info = "Fuzzing RESPONSES; " + run_additional_info
        print(term.render("Fuzzing ${BOLD}RESPONSES${NORMAL}"))
    else:
        fuzz_response = False

    if(not(options.fuzz_response or options.fuzz_request)):
        run_additional_info = "Fuzzing NONE; " + run_additional_info
        print(term.render("Fuzzing ${BOLD}<NOTHING>${NORMAL} (Maybe you wanted ${BOLD}--fuzz-request or --fuzz-response${NORMAL}?)"))

    if(fuzz_request and fuzz_response):
        print(term.render("${YELLOW}\nWARNING! WARNING!\n${BOLD}Fuzzing BOTH the request and response is probably a bad idea, ensure this is what you want to do!${NORMAL}${YELLOW}\nWARNING! WARNING!\n${NORMAL}"))

    # host, db, username, passwd
    if logging_enabled:
        logger = postgresLogger("postgreshost", "dbname", "dbuser", "dbpass")

        logger.log_run_info("CompanyName", "ProjectName-v1.2.3", run_additional_info)

    # create object that spawns reciever/sender pairs upon connection
    fwdr = forwarder(options.local_addr,options.local_port,options.remote_addr,options.remote_port)
    print("Listener running...")
    #asyncore.loop()

    # A quick hack to be able to control fuzz on/off while running
    # separate asyncore.loop into its own thread so we can have terminal control
    asyncThread = Thread(target=asyncore.loop)
    asyncThread.start()

    # start a console (ipython)
    from IPython.terminal.interactiveshell import TerminalInteractiveShell
    shell = TerminalInteractiveShell(user_ns=globals())
    shell.mainloop()

    # cleanup otherwise thread wont die and program hangs
    fwdr.close()
    #asyncore.close_all()
    asyncThread._Thread__stop()


if __name__=='__main__':
    main()
