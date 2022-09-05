# pip3 install pyshark var_dump
import pyshark
from var_dump import var_dump
import json 

import glob

# single.query.sizes contains a resolution with session resumption (if supported) of the A record for google.com
# to all the used resolvers, for all the supported DNS protocols

# This script reads all the pcaps, calculates a variety of metrics, and spits those out into a .csv

outputName = "single.query.sizes.csv"
fileList = glob.glob("single.query.sizes/*.pcap")

output = {}

DEBUG_counter = 0

for filepath in fileList:
    DEBUG_counter += 1
    capture = pyshark.FileCapture(filepath, decode_as={'udp.port==784':'quic','udp.port==853':'quic','udp.port==8853':'quic' })


    # [protocol]
    #   - [resolver_ip]
    #       - .packet_count             # amount of packets in the proxy->resolver and resolver -> proxy comms
    #       - [layer4up]                # amount of data contained in IP packets
    #           - .DNS_baseline_out     # amount of total data in the client -> proxy DoUDP packets 
    #           - .DNS_baseline_in      # amount of total data in the proxy -> client DoUDP packets
    #           - .DNS_size_out         # amount of total data in the proxy -> resolver DoXYZ packets
    #           - .DNS_size_in          # amount of total data in the resolver -> proxy DoXYZ packets
    #           - .handshake_out        # amount of handshake data in the resolver -> proxy DoXYZ packets
    #           - .handshake_in         # amount of handshake data in the resolver -> proxy DoXYZ packets
    #           - .query                # amount of pure DNS query data
    #           - .response             # amount of pure DNS response data
    # 
    #       - [layer0up]                # amount of data contained in physical frames
    #           - .DNS_baseline_out     # amount of total data in the client -> proxy DoUDP packets 
    #           - .DNS_baseline_in      # amount of total data in the proxy -> client DoUDP packets
    #           - .DNS_size_out         # amount of total data in the proxy -> resolver DoXYZ packets
    #           - .DNS_size_in          # amount of total data in the resolver -> proxy DoXYZ packets

    CLIENT_IP = "127.0.0.1"
    PROXY_INTERNAL_IP = "127.0.0.2"
    PROXY_EXTERNAL_IP = "172.31.9.60"
    RESOLVER_IP = None # to be set for each capture file

    # example filename: capture-udp-141.95.140.195-2022-04-21_13_55_38.pcap
    filename_parts = filepath[ filepath.rindex("/") : ].split("-")
    dns_protocol = filename_parts[1]
    intended_resolver_ip = filename_parts[2]

    RESOLVER_IP = intended_resolver_ip

    # TCP/TLS/QUIC connections sometimes stay open long after the DNS query has been done
    # this would inflate total sizes by including things like pings, so we stop measuring overheads
    # when the proxy has sent the response back to the client
    measuring = False # True once the Proxy has received request from client, False once Proxy has sent response back to client

    if dns_protocol not in output:
        output[dns_protocol] = {}

    output[dns_protocol][RESOLVER_IP] = {}
    output[dns_protocol][RESOLVER_IP]["packet_count"] = 0
    output[dns_protocol][RESOLVER_IP]["layer4up"] = {}
    output[dns_protocol][RESOLVER_IP]["layer4up"]["DNS_baseline_out"] = 0
    output[dns_protocol][RESOLVER_IP]["layer4up"]["DNS_baseline_in"] = 0
    output[dns_protocol][RESOLVER_IP]["layer4up"]["DNS_size_out"] = 0
    output[dns_protocol][RESOLVER_IP]["layer4up"]["DNS_size_in"] = 0
    output[dns_protocol][RESOLVER_IP]["layer4up"]["handshake_out"] = 0
    output[dns_protocol][RESOLVER_IP]["layer4up"]["handshake_in"] = 0
    output[dns_protocol][RESOLVER_IP]["layer4up"]["query"] = 0
    output[dns_protocol][RESOLVER_IP]["layer4up"]["response"] = 0
    output[dns_protocol][RESOLVER_IP]["layer0up"] = {}
    output[dns_protocol][RESOLVER_IP]["layer0up"]["DNS_baseline_out"] = 0
    output[dns_protocol][RESOLVER_IP]["layer0up"]["DNS_baseline_in"] = 0
    output[dns_protocol][RESOLVER_IP]["layer0up"]["DNS_size_out"] = 0
    output[dns_protocol][RESOLVER_IP]["layer0up"]["DNS_size_in"] = 0

    # shortcut for easier coding
    result = output[dns_protocol][RESOLVER_IP]
    result4 = result["layer4up"]
    result0 = result["layer0up"] 

    for pkt in capture:

        try:
            protocol = pkt.transport_layer
            src_addr = pkt.ip.src
            src_port = pkt[pkt.transport_layer].srcport
            dst_addr = pkt.ip.dst
            dst_port = pkt[pkt.transport_layer].dstport

            # also do this after started capturing, in case query split over multiple packets
            if src_addr == CLIENT_IP and dst_addr == PROXY_INTERNAL_IP:
                measuring = True
                result4["DNS_baseline_out"] += int(pkt[pkt.transport_layer].length, 10) # UDP header size is always 8
                result0["DNS_baseline_out"] += int(pkt.length, 10)
            
            # also do this after started capturing, in case response split over multiple packets
            if src_addr == PROXY_INTERNAL_IP and dst_addr == CLIENT_IP:
                measuring = False
                result4["DNS_baseline_in"] += int(pkt[pkt.transport_layer].length, 10) # UDP header size is always 8
                result0["DNS_baseline_in"] += int(pkt.length, 10)

            if measuring and (src_addr == PROXY_EXTERNAL_IP or src_addr == RESOLVER_IP):
                result["packet_count"] += 1

                handshake_size = 0
                query_size = 0

                # calculate the total transport + up packet size
                # - UDP has a .length field that INCLUDES the header's 8 byte overhead => use that
                # - TCP has a .len field that DOES NOT include the header length
                    # - add .hdr_len to that to get the full TCP length
                layer4plus_size = 0
                if protocol == "TCP":
                    layer4plus_size = int(pkt[pkt.transport_layer].len, 10) + int(pkt[pkt.transport_layer].hdr_len, 10)

                    flags = pkt[pkt.transport_layer].flags.showname_value # e.g., 0x012 (SYN, ACK)
                    if ("(SYN, ACK)" in flags) or ("(SYN)" in flags):
                       handshake_size += layer4plus_size

                    # detect last ACK of 3-way handshake with relative seqnr 1 and acknowledging relative 1
                    elif "(ACK)" in flags and int(pkt.tcp.seq, 10) == 1 and int(pkt.tcp.ack,10) == 1:
                       handshake_size += layer4plus_size

                    else:
                        query_size += layer4plus_size

                elif protocol == "UDP":
                    layer4plus_size += int(pkt[pkt.transport_layer].length, 10)
                    query_size += layer4plus_size # DoUDP has no handshake, DoQ resets this below
                else:
                    print( "TODO: transport protocol unknown!! ", protocol)
                    print( var_dump(pkt[pkt.transport_layer]) )


                if (dns_protocol == "tls" or dns_protocol == "https") and "tls" in pkt:
                    if handshake_size > 0: # TCP is in handshake, SHOULD NOT HAPPEN
                        print("ERROR : TLS handshake overlaps with TCP, SHOULD NOT HAPPEN!")
                    
                    handshake_size = 0
                    query_size = 0

                    # TLS parsing is a bit broken in pyshark apparently
                    # not a single object, but multiple fields for which you have to do .all_fields manually, swell!
                    #  https://github.com/KimiNewt/pyshark/issues/419

                    record_count = len(pkt.tls.record.all_fields)


                    for i in range(0, record_count):

                        #  this is the record payload size + auth tag (or at least it appears so)
                        record_length = int( pkt.tls.record_length.all_fields[i].showname_value, 10 )

                        record_length += 5 # TLS 1.3 record header is 5 bytes in size

                        if "Application Data Protocol" in pkt.tls.record.all_fields[i].showname:
                            query_size += record_length
                        else:
                            handshake_size += record_length

                    # problem: single TCP packet contains both TLS handshake data and TLS app data
                    #   -> which of both gets to carry the TCP header overhead? I decided on handshake for now
                    if handshake_size > 0: # there was a handshake record in there
                        handshake_size += int(pkt[pkt.transport_layer].hdr_len, 10)
                    else:
                        query_size += int(pkt[pkt.transport_layer].hdr_len, 10)

                if dns_protocol == "quic" and "quic" in pkt:

                    handshake_size = 0
                    query_size = 0

                    long_packet_type = -1
                    # for some reason,   if "long_packet_type" in pkt.quic   does not work... aargh
                    try: 
                        long_packet_type = pkt.quic.long_packet_type
                        # print( "PACKET WAS LONG!", long_packet_type )
                    except Exception:
                        # print( "PACKET WAS SHORT!" )
                        pass

                    # packet_length is the actual full packet length: header, payload, auth tag
                    # length is the length field in the QUIC packet header
                    
                    # however, in this case, we can just keep using the layer4plus_size, which is the full UDP packet!
                    if long_packet_type == -1:
                        query_size += layer4plus_size
                    else:
                        handshake_size += layer4plus_size
                    


                if src_addr == PROXY_EXTERNAL_IP:
                    result4["DNS_size_out"] += layer4plus_size
                    result0["DNS_size_out"] += int(pkt.length, 10)

                    result4["handshake_out"] += handshake_size
                    result4["query"] += query_size
                else:
                    result4["DNS_size_in"] += layer4plus_size
                    result0["DNS_size_in"] += int(pkt.length, 10)

                    result4["handshake_in"] += handshake_size
                    result4["response"] += query_size



        except AttributeError as e:
            #ignore packets that aren't TCP/UDP or IPv4
            # print( "ERROR: Tried to access unknown attribute!" )
            pass

    print(f"Processed capture {DEBUG_counter}/{len(fileList)}")

    capture.close()

    # sanity checks
    if dns_protocol == "udp" and ((result4["DNS_baseline_in"] != result4["DNS_size_in"]) or (result4["DNS_baseline_out"] != result4["DNS_size_out"])):
        print("ERROR: DoUDP should have no overhead!", filepath)
        print( var_dump(result4) )

    if result4["DNS_size_out"] == 0 or result4["DNS_size_in"] == 0:
        print("ERROR: No DNS sizes discovered, shouldn't happen!", filepath)
        print( var_dump(result4) )  

    if ((result4["handshake_out"] + result4["query"] != result4["DNS_size_out"]) or 
       (result4["handshake_in"] + result4["response"] != result4["DNS_size_in"])):
        print("ERROR: handshake and DNS data don't add up!", filepath)
        print( var_dump(result4) )  

with open( outputName, 'w') as f:
    print("Writing results")
    f.write("protocol;resolver;packetcount;baseline_out;baseline_in;full_out;full_in;handshake_out;handshake_in;query;response\n")

    for protocol in output:
        for resolver in output[protocol]:

            results = output[protocol][resolver]

            f.write(f'{protocol};{resolver};{results["packet_count"]};{results["layer4up"]["DNS_baseline_out"]};{results["layer4up"]["DNS_baseline_in"]};{results["layer4up"]["DNS_size_out"]};{results["layer4up"]["DNS_size_in"]};{results["layer4up"]["handshake_out"]};{results["layer4up"]["handshake_in"]};{results["layer4up"]["query"]};{results["layer4up"]["response"]}\n')
