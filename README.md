# Codec payload Extractor
Extracts AMR, AMR-WB or EVS frames from RTP inside PCAP files and builds a *.3ga* file (for AMR and AMR-WB) or a *.evs-mime* (for EVS). 

## Dependencies
This script requires [python3](https://www.python.org/) and its modules [scapy](https://github.com/secdev/scapy) and [bitarray](https://pypi.org/project/bitarray/).

## Usage
>python pcap_parser.py -i <_rtpfilteredpcap_> [-o <_outputamrwbencodedaudio_>] [-c codec] [-f framing]

where:

* **rtpfilteredpcap** must be a pcap or pcapng file filtered to include only RTP data. In principle, it should contain only the RTP flow that you want to extract into an audio file for listening on your PC.
* **outputamrwbencodedaudio** is the name of the output file with the extracted AMR / AMR-WB audio.
* **codec** can take values 'amr', 'amr-wb' or 'evs'. If no value is specified, then the script will try to guess the codec and exit with a message if the codec could not be guessed.
* **framing** can take values 'ietf' (RFC4867 bandwidth efficient) or 'iu' (3GPP TS25.415). Default value is 'ietf'. ***Note:** Iu framing is not supported for EVS codec yet.*

## Tools
### AMR and AMR-WB
The latest version of [VLC](https://www.videolan.org/) plays back .3ga files.

If you want to play the output file in a media player that does not support AMR / AMR-WB, then use [ffmpeg](https://ffmpeg.org/) to convert AMR / AMR-WB to MP3, PCM or any other format. The following command, for example, converts AMR to PCM:

>ffmpeg.exe -i amrwbencodedfile.amr pcmencodedfile.wav

### EVS
I have not found any media player that can play files with the EVS content format specified in section A.2.6 of 3GPP TS26.445. I you find one, please share the info.

Your best chance to play the content of the generated **.evs-mime** files is to convert them to raw PCM using the decoder provided by 3GPP. The C source code and a windows executable of this decoder can be found inside 3GPP TS26.442 (fixed-point) and TS26.443 (floating-point). The source code can easily be compiled for Windows and Linux.

***Note:** 3GPP specifications are freely available at the [3GPP site](http:\\www.3gpp.org).

To generate a raw file with the 3GPP decoder use the following command on a console:

>EVS_dec.exe -mime 48 my_evs_mime_file.evs-mime out_raw_file.raw

The raw file can be imported by [Audacity](https://www.audacityteam.org/) with *import -> raw data*. The parameters for import are:

- Encoding: Signed 16-bit PCM
- Byte order: Little endian
- Channels: 1 Channel (Mono)
- Start offset: 0 bytes
- Sampling rate: 48000

## Limitations
This version has the following limitations:

- Supports only single channel for all codecs suppoted. I.e. multichannel is not supported.
- Supports only 1 codec frame per packet.
- For EVS codec, only the compact payload format is supported (section A.2.1 of 3GPP TS26.445). Header-full format (section A.2.2 of 3GPP TS26.445) is not supported.
- Iu Framing is not supported for the EVS codec

## Background
IETF RFC4867 defines the RTP payload formats and storage formats for AMR and AMR_WB codecs. The "bandwidth efficient" described in section 4.3 is used inside mobile core networks to convey codec frames using RTP. The storage format in section 5 is used for audio files encoded with AMR or AMR-WB codecs.

Annex A of 3GPP TS26.445 defines the RTP Payload formats for EVS, including EVS AMR-WB IO mode used for transcoder free communication between AMR-WB capable client and EVS client.

3GPP TS24.415 defines the framing protocol for user plane data used in the Iu interface (between MSC/SGSN and RNC). PDU Type 0 is the usual frame format used to convey AMR / AMR-WB / EVS codec frames.

## ToDo
I will add the following functionality as time allows:

* Handle trace files (pcap or pcapng) with multiple RTP flows, extracting each flow to a different audio file.
* Handle unfiltered trace files.
* Support G711 codec.
* Support Iu framing for EVS.
* Support Header-full format for EVS.
