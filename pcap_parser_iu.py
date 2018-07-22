'''
Pcap file parser with Iu framing protocol.
This script parses a pcap file to extract rtp amr-wb data, encapsulated 
using IuUP framing protocol (TS25.214), and stores it in a file
file with the storage format defined in section 5 of RFC4864.

The pcap file must contain only one RTP flow with amr-wb codec data. Any 
other codec will produce invalid output. 
If the pcap file includes more than one RTP flow, then only the first one
found is extracted.
'''
import sys
#sys.path.insert(0, "E:\Proyectos\RTP_AMRWB\rtpamrw_env\Lib\site-packages")
import argparse
from scapy.all import *
from bitarray import bitarray

# Total number of bits for modes 0 to 8 (Table 2 in TS26.201)
amrwb_ft = [132, 177, 253, 285, 317, 365, 397, 461, 477, 40]
# this dictionary maps expected IUFH payload lengths (in octets) to AMR-WB modes
amrwb_ft_map = {
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

# RTP params in RTP header
seq = -1
syncsrcid = 0 
ptype = 0

# IuUP framing protocol params
fn = -1 # Frame number
num_frames = 0
num_control = 0
num_valid = 0
num_bad = 0

def storePayload(outfile, amrpl):
    '''
    Writes the AMR-WB payload inside rtp_packet to the output file as 
    described in section 5 of RFC4864.
    :param outfile: output file
    :type: FILE handler
    :param rtp_packet: RTP packet
    :type: scapy RTP packet structure
    :rtype: void
    '''
    global fn, num_control, num_valid, num_bad
    print('DEBUG -> RTP payload: {}'.format(amrpl))
    header = struct.unpack("!H", amrpl[0:2])[0] # only the first to octets contain relevant info
    pdu_type = header & 0xF000
    frame_number = header & 0x0F00
    fqc = header & 0x00C0
    isvalid = False
    if pdu_type == 0xE000: # PDU type 14 -> Control frame
        num_control += 1
    else:
        if fn != frame_number: # first
            fn = frame_number
            isvalid = True
            num_valid += 1
    if isvalid == True:
        q = 1 if fqc == 0 else 0
        if q == 0:
            num_bad += 1
        hdr_len = 4 if pdu_type == 0 else 3
        ft_index = len(amrpl) - hdr_len
        ft = amrwb_ft_map[ft_index]
        print('DEBUG -> hdr_len = {} , ft_index = {} , ft = {}'.format(hdr_len, ft_index, ft))
        toc_bits = (ft << 3) ^ (q << 2)
        toc = toc_bits.to_bytes(1, byteorder = 'big')
        bitline = bitarray(endian='big')
        bitline.frombytes(toc)
        # load the bits 
        buf = bitarray(endian='big')
        buf.frombytes(amrpl[hdr_len:])
        # remove padding bits
        #print('DEBUG -> FT = {}, Q = {} , TOC = {}'. format(ft >> 7, q >> 6, toc))
        if len(buf) >= amrwb_ft[ft]:
            buf = buf[:amrwb_ft[ft]]
        bitline += buf # toc + codec frame
        #bitline.append(False * (len(bitline) % 8)) # add padding
        bitline.tofile(outfile) # 0 padding is done by bitarray to achieve byte aligment
        print('DEBUG -> Line: {}'.format(bitline.tobytes()))
    else:
        print('DEBUG -> Invalid frame')

def usage():
    '''Prints command line'''
    print('Usage: pcap_parser_iu.py -i pcap_file [-o] output_file')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', action="store", dest = "infile", help = 'PCAP file to scan')
    parser.add_argument('-o', action="store", dest = "outfile", default = "out.amr-wbffm", help = 'Output AMR-WBfile')
    args = parser.parse_args()

    if not args.infile:
        usage()
        exit(-1)
    
    packets = rdpcap(args.infile)
    if len(packets) <= 0:
        print("Empty or invalid input file (not pcap?)")
        exit(-2)
    else:
        print("Number of packets read from pcap: {}".format(len(packets)))
    with open(args.outfile, 'wb') as ofile:
        for packet in packets:
            isvalid = False
            rtp = RTP(packet[UDP].load)
            if seq == -1: # first RTP packet
                print('DEBUG First packet content:')
                rtp.show()
                seq = rtp.sequence
                syncsrcid = rtp.sourcesync
                ptype = rtp.payload_type
                ofile.write("#!AMR-WB\n".encode()) # Write magic number to output file
                isvalid = True
            elif seq != rtp.sequence and syncsrcid == rtp.sourcesync and ptype == rtp.payload_type:
                isvalid = True
            if isvalid == True:
                num_frames += 1
                storePayload(ofile, rtp.load)
    print('Total: {} , Valid: {}, Control: {} , Bad: {}'.format(num_frames, num_valid, num_control, num_bad))

