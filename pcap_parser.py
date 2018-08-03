'''
Pcap file parser for AMR / AMR-WB / EVS with RFC4867 or Iu framing.
This script parses a pcap file to extract rtp amr, amr-wb or evs data, 
encapsulated using the bandwidth efficient mode described in RFC4867 or 
using Iu framing (3GPP TS25.415), and stores it in a file with the storage 
format defined in section 5 of RFC4867.

The pcap file must contain only one RTP flow with amr, amr-wb or evs codec data. 
Any other codec will produce invalid output or crash.
If the pcap file includes more than one RTP flow, then only the first one
found is extracted.

The codec type, 'amr', 'amr-wb' or evs can be specified in the command line with 
the -c option. If not specified, then the script will try to guess the codec. 
Guessing works very well in normal cases, so you should always try to let the 
script guess and only specify a codec if the script tells you that it was not 
able to guess.

Limitations:
   - Supports only single channel for all codecs suppoted. I.e. multichannel is not supported.
   - Supports only 1 codec frame per packet.
   - For EVS codec, only the compact payload format is supported (section A.2 of 3GPP TS26.445)
   - Iu Framing is not supported for the EVS codec
'''

__version__ = '0.3.0'
__author__ = 'Juan Noguera'

import sys
#sys.path.insert(0, "E:\Proyectos\RTP_AMRWB\rtpamrw_env\Lib\site-packages")
import argparse, logging
from scapy.all import *
from bitarray import bitarray

supported_codecs = ['guess', 'amr', 'amr-wb', 'evs']

codec = -1   # -1-> undefined, 0 -> amr, 1 -> amr-wb
seq = -1
syncsrcid = 0
ptype = 0

num_frames = 0
num_valid_frames = 0    # Number of frames of the first RTP flow in the trace. Should be the same as num_frames if there is only one RTP flow in the trace
num_bad_frames = 0

# IuUP framing protocol params
fn = -1 # Frame number in Iu framing
num_control_frames = 0

def storePayloadIetf(outfile, codec, payload):
    '''
    Writes the codec payload inside rtp_packet to the output file as 
    described in section 5 of RFC4864.
    :param outfile: output file
    :type: FILE handler
    :param codec_ft: bit sizes for the different codec frame types
    :type: array of int
    :param payload: codec payload inside RTP packet
    :type: bytes
    :rtype: void
    '''

    global num_bad_frames
    
    if codec == 'amr' or codec == 'amr-wb':
        if codec == 'amr':
            # Total number of bits for modes 0 to 8 (Tables 2 and A.1b in TS26.101)
            codec_ft = [95, 103, 118, 134, 148, 159, 204, 244, 39]
        elif codec == 'amr-wb': # amr-wb
            # Total number of bits for modes 0 to 9 (Table 2 in TS26.201)
            codec_ft = [132, 177, 253, 285, 317, 365, 397, 461, 477, 40]

        header = struct.unpack("!H", payload[0:2])[0]
        ft = header & 0x0780
        q = header & 0x0040
        if q == 0:
            num_bad_frames += 1
        toc_bits = (ft >> 4) ^ (q >> 4)
        toc = toc_bits.to_bytes(1, byteorder = 'big')
        bitline = bitarray(endian='big')
        bitline.frombytes(toc)
        # load the bits 
        buf = bitarray(endian='big')
        buf.frombytes(payload[1:])
        # remove the first two bits (corresponding to 4th FT bit and Q)
        buf = buf[2:]
        #print('DEBUG -> FT = {}, Q = {} , TOC = {}'. format(ft >> 7, q >> 6, toc))
        ft = ft >> 7
        if len(buf) >= codec_ft[ft]:    # remove padding
            buf = buf[:codec_ft[ft]] 
        bitline += buf # toc + codec frame
        #bitline.append(False * (len(bitline) % 8)) # add padding
        bitline.tofile(outfile) # 0 padding is done by bitarray to achieve byte aligment
        # print('DEBUG -> RTP payload: {}'.format(amrpl))
        # print('DEBUG -> Line: {}'.format(bitline.tobytes()))
    else: # evs
        # We do NOT distinguish between pure EVS and EVS AMR-WB IO mode
        is_io_modes = [0, -1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0]  # 0 = EVS, 1 = EVS AMR-WB IO, -1 = ambiguous (Table A.1 in 3GPP TS 26.445)
        evs_payload_sizes = [6, 7, 17, 18, 20, 23, 24, 32, 33, 36, 40, 41, 46, 50, 58, 60, 61, 80, 120, 160, 240, 320]
        toc = [b'\x0C', b'\x00', b'0', b'\x01', b'\x02', b'1', b'\x03', b'2', b'\x04', b'3', b'4', b'\x05', b'5', b'6', b'7', b'8', b'\x06', b'\x07', b'\x08', b'\x09', b'\x0A', b'\x0B']
        is_io = is_io_modes[evs_payload_sizes.index(len(payload))]
        if is_io == 0: # evs
            outfile.write(toc[evs_payload_sizes.index(len(payload))])
            outfile.write(payload)
            logging.debug('EVS\ttoc: {}\tlen: {}'.format(toc[evs_payload_sizes.index(len(payload))], len(payload)))
        elif is_io == 1: # evs amr-wb io -> remove CMR bits
            toc_byte = bitarray(endian='big')
            toc_byte.frombytes(toc[evs_payload_sizes.index(len(payload))])
            buf = bitarray(endian='big')
            buf.frombytes(payload)
            buf = toc_byte + buf[3:]
            buf.tofile(outfile)
            logging.debug('AMR-WB IO\ttoc: {}\tlen: {}'.format(toc_byte, len(payload)))
        else: # ambigous case
            bit0 = struct.unpack("!B", amrpl[0:1])[0] & 0x80
            if bit0 == 0:    # it is evs primary 2.8kbps
                outfile.write(toc[1] + payload)
                logging.debug('EVS 2.8\ttoc: {}\tlen: {}'.format(toc[1], len(payload)))
            else: # it is evs amr-wb io sid in header-full with one CMR byte
                buf = bitarray(endian='big')
                buf.frombytes(payload)
                buf = buf[8:]  # remove CMR byte but leave TOC byte
                buf.tofile(outfile)
                logging.debug('EVS AMR-WB IO SID'.format(toc[1], len(payload)))
        

def storePayloadIu(outfile, codec, amrpl):
    '''
    Writes the codec payload inside rtp_packet to the output file as 
    described in section 5 of RFC4864.
    :param outfile: output file
    :type: FILE handler
    :param rtp_packet: RTP packet
    :type: scapy RTP packet structure
    :rtype: void
    '''
    global fn, num_control_frames, num_bad_frames

    if codec == 'amr':
        # Total number of bits for modes 0 to 8 (Tables 2 and A.1b in TS26.101)
        codec_ft = [95, 103, 118, 134, 148, 159, 204, 244, 39]
        # this dictionary maps expected IUFH payload lengths (in octets) to AMR-WB modes
        codec_ft_map = {
            12: 0,
            13: 1,
            15: 2,
            17: 3,
            19: 4,
            20: 5,
            26: 6,
            31: 7,
            5: 8
        }
    else: # amr-wb
        # Total number of bits for modes 0 to 9 (Table 2 in TS26.201)
        codec_ft = [132, 177, 253, 285, 317, 365, 397, 461, 477, 40]
        # this dictionary maps expected IUFH payload lengths (in octets) to AMR-WB modes
        codec_ft_map = {
            17: 0,
            23: 1,
            32: 2,
            36: 3,
            40: 4,
            46: 5,
            50: 6,
            58: 7,
            60: 8,
            5: 9
        }

    #print('DEBUG -> RTP payload: {}'.format(amrpl))
    header = struct.unpack("!H", amrpl[0:2])[0] # only the first to octets contain relevant info
    pdu_type = header & 0xF000
    frame_number = header & 0x0F00
    fqc = header & 0x00C0
    isvalid = False
    if pdu_type == 0xE000: # PDU type 14 -> Control frame
        num_control_frames += 1
    else: # skip repeated frames
        if fn != frame_number:
            fn = frame_number
            isvalid = True
    if isvalid == True:
        q = 1 if fqc == 0 else 0
        if q == 0:
            num_bad_frames += 1
        hdr_len = 4 if pdu_type == 0 else 3
        ft_index = len(amrpl) - hdr_len
        ft = codec_ft_map[ft_index]
        #print('DEBUG -> hdr_len = {} , ft_index = {} , ft = {}'.format(hdr_len, ft_index, ft))
        toc_bits = (ft << 3) ^ (q << 2)
        toc = toc_bits.to_bytes(1, byteorder = 'big')
        bitline = bitarray(endian='big')
        bitline.frombytes(toc)
        # load the bits 
        buf = bitarray(endian='big')
        buf.frombytes(amrpl[hdr_len:])
        # remove padding bits
        #print('DEBUG -> FT = {}, Q = {} , TOC = {}'. format(ft >> 7, q >> 6, toc))
        if len(buf) >= codec_ft[ft]:
            buf = buf[:codec_ft[ft]]
        bitline += buf # toc + codec frame
        #bitline.append(False * (len(bitline) % 8)) # add padding
        bitline.tofile(outfile) # 0 padding is done by bitarray to achieve byte aligment
        #print('DEBUG -> Line: {}'.format(bitline.tobytes()))
    else:
        print('Invalid frame')

def guessCodec(packets, framing):
    '''
    Parsers the RTP payloads inside the packets to try to guess the codec used.
    The function exits as soon as the codec is resolved.
    :param packets: list of packets 
    :type: scapy packets
    :rtype: int (-1 -> unable to guess, 0 -> amr, 1 -> amr-wb)
    '''
    # Size of RTP payload, in octets, for the different codec modes (including 
    # header for bandwith efficient mode in RFC4867)
    amr_payload_sizes = [13, 14, 16, 18, 20, 21, 27, 32, 6]
    amrwb_payload_sizes = [18, 24, 33, 37, 41, 47, 51, 59, 61, 7]
    evs_payload_sizes = [6, 7, 17, 18, 20, 23, 24, 32, 33, 36, 40, 41, 46, 50, 58, 60, 61, 80, 120, 160, 240, 320]
    # Size of RTP payload, in octets, for the different codec modes (including 
    # header for Iu payload type 0)
    amr_payload_sizes_iupt0 = [16, 17, 19, 21, 23, 24, 30, 35, 9]
    amrwb_payload_sizes_iupt0 = [21, 27, 36, 40, 44, 50, 54, 62, 64, 9]
    amr_payload_sizes_iupt1 = [15, 16, 18, 20, 22, 23, 29, 34, 8]
    amrwb_payload_sizes_iupt1 = [20, 26, 35, 39, 43, 49, 53, 61, 63, 8]

    syncsrcid = -1  # used to consider only the first rtp flow found
    ptype = -1      # used to consider only the first rtp flow found
    count = 100     # number of packet samples to check
    packets_codec = {'amr': 0, 'amr-wb': 0, 'evs': 0}
    for packet in packets:
        # print('DEBUG -> Count: {}'.format(count))
        classified = False
        # packet.show()
        if ICMP in packet:
            continue
        rtp = getRtpAsPacket(packet)
        if rtp == None:
            continue
        if syncsrcid == -1:
            syncsrcid = rtp.sourcesync
            ptype = rtp.payload_type
        elif syncsrcid != rtp.sourcesync or ptype != rtp.payload_type:
            continue
        else:
            payload_len = len(rtp.load)
            if framing == 'ietf':
                isamr = payload_len in amr_payload_sizes
                isamrwb = payload_len in amrwb_payload_sizes
                isevs = payload_len in evs_payload_sizes
                
                ft = (struct.unpack("!H", rtp.load[0:2])[0] & 0x0780) >> 7
                if isamr: # check that the ft corresponds wih size
                    if ft < 9 and payload_len == amr_payload_sizes[ft]: # mode 0
                        packets_codec['amr'] += 1
                        classified = True
                if isamrwb and not classified:
                    if ft < 10 and payload_len == amrwb_payload_sizes[ft]: # mode 0
                        packets_codec['amr-wb'] += 1
                        classified = True
                elif isevs and not classified:
                    packets_codec['evs'] += 1
                    classified = True
            else: # framing == 'iu'
                isamr = (payload_len in amr_payload_sizes_iupt0) or (payload_len in amr_payload_sizes_iupt1)
                isamrwb = (payload_len in amrwb_payload_sizes_iupt0) or (payload_len in amrwb_payload_sizes_iupt1)
                isevs = False
                if isamr and not isamrwb:
                    packets_codec['amr'] += 1
                    classified = True
                elif isamrwb and not isamr:
                    packets_codec['amr-wb'] += 1
                    classified = True
        if classified:
            count -= 1
        if count <= 0:
            break
    print('AMR samples: {}, AMR-WB samples: {}, EVS samples: {}'.format(packets_codec['amr'], packets_codec['amr-wb'], packets_codec['evs']))
    if packets_codec['amr'] > 0 and packets_codec['amr-wb'] == packets_codec['evs'] == 0:
        return 'amr'
    if packets_codec['amr-wb'] > 0 and packets_codec['amr'] == packets_codec['evs'] == 0:
        return 'amr-wb'
    if packets_codec['evs'] > 0:
        return 'evs'
    return None   # could not guess

def getRtpAsPacket(packet):
    '''
    Search inside the packet for the RTP content.
    This is straightforward for "normal" ETH encapsulation. But there are some ETH extensions, 
    like 802.1ad (or QinQ), are not supported by scapy. Normally, this should be solved by 
    extending scapy, but for the time being, I solve it with this function.
    :param packet: packet that is supposed to have IP/UDP/RTP structure 
    :type: scapy packet
    :rtype: RTP scapy packet or None
    '''
    if UDP in packet:
        return RTP(packet[UDP].load)
    if Ether in packet:
        if packet[Ether].type == 0x9100:  # old 802.1ad (QinQ)
            vlan = Dot1Q(packet[Ether].load)
            # vlan.show()  # DEBUG
            if UDP in vlan:
                return RTP(vlan[UDP].load)
            else:
                return None
    return None

def usage():
    '''Prints command line'''
    print('Usage: pcap_parser.py -i pcap_file [-o] output_file [-c] codec (amr, amr-wb or evs)')
    print('Try first without specifying a codec with -c option. Use -c only if this script could not guess codec type.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', action="store", dest = "codec", default = "guess", help = 'codec [amr, amr-wb, evs], default = guess codec')
    parser.add_argument('-f', action="store", dest = "framing", default = "ietf", help = 'framing [ietf, iu], default = ietf')
    parser.add_argument('-i', action="store", dest = "infile", help = 'PCAP file to scan')
    parser.add_argument('-o', action="store", dest = "outfile", default = "out.3ga", help = 'Output audio file')

    args = parser.parse_args()

    logging.basicConfig(filename = 'pcap_parser.log', filemode = 'w', level = logging.DEBUG)

    if not args.infile:
        usage()
        exit(-1)
    
    if args.codec not in supported_codecs:
        print("Unsupported codec: {}".format(args.codec))
        exit(-2)
    codec = args.codec

    if args.framing != "ietf" and args.framing != "iu":
        print("Unsupported framing: {}".format(args.framing))
        exit(-2)
    framing = args.framing
    
    packets = rdpcap(args.infile) # read packets from pcap or pcapng file

    if len(packets) <= 0:
        print("Empty or invalid input file (not pcap?)")
        exit(-3)
    else:
        print("Number of packets read from pcap: {}".format(len(packets)))

    if codec == 'guess':
        codec = guessCodec(packets, framing)
        if codec == None:
            print("Unable to guess the codec used.")
            exit(-4)

    with open(args.outfile, 'wb') as ofile:
        # Write magic number to output file
        if codec == 'amr':
            ofile.write("#!AMR\n".encode())
        elif codec == 'amr-wb':
            ofile.write("#!AMR-WB\n".encode())
        else:
            ofile.write("#!EVS_MC1.0\n".encode())
            ofile.write(b'\x00\x00\x00\x01')
        for packet in packets:
            isvalid = False
            num_frames += 1
            rtp = getRtpAsPacket(packet)
            if rtp == None:
                continue
            #rtp = RTP(packet[UDP].load)
            if seq == -1: # first RTP packet
                #print('DEBUG First packet content:')
                #rtp.show()
                seq = rtp.sequence
                syncsrcid = rtp.sourcesync
                ptype = rtp.payload_type
                isvalid = True
            elif seq != rtp.sequence and syncsrcid == rtp.sourcesync and ptype == rtp.payload_type:
                isvalid = True
            if isvalid == True:
                num_valid_frames += 1
                if framing == 'ietf':
                    storePayloadIetf(ofile, codec, rtp.load)
                else:
                    storePayloadIu(ofile, codec, rtp.load)
    if framing == 'ietf':
        print('Codec: {}, Total: {} , Valid: {} , Bad: {}'.format(codec, num_frames, num_valid_frames, num_bad_frames))
    else:
        print('Codec: {} , Total: {}, Valid: {}, Control: {} , Bad: {}'.format(codec, num_frames, num_valid_frames, num_control_frames, num_bad_frames))
    
