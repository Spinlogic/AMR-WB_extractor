# Codec payload Extractor
Extracts AMR and AMR-WB frames from RTP inside PCAP files and builds a **.amr* file that can be played back in some media players.

## Dependencies
This script requires [python3](https://www.python.org/) and its modules [scapy](https://github.com/secdev/scapy) and [bitarray](https://pypi.org/project/bitarray/).

## Usage
>python pcap_parser.py -i <_rtpfilteredpcap_> [-o <_outputamrwbencodedaudio_>] [-c codec] [-f framing]

where:

* **rtpfilteredpcap** must be a pcap or pcapng file filtered to include only RTP data. In principle, it should contain only the RTP flow that you want to extract into an audio file for listening on your PC.
* **outputamrwbencodedaudio** is the name of the output file with the extracted AMR / AMR-WB audio.
* **codec** can take values 'amr' or 'amr-wb'. If no value is specified, then the script will try to guess the codec and exit with a message if the codec could not be guessed.
* **framing** can take values 'ietf' (RFC4867 bandwidth efficient) or 'iu' (3GPP TS25.415). Default value is 'ietf'

## Tools
The latest version of [VLC](https://www.videolan.org/) plays back .amr files.

If you want to play the output file in a media player that does not support AMR, then use [ffmpeg](https://ffmpeg.org/) to convert AMR to MP3, PCM or any other format. The following command, for example, converts AMR to PCM:

>ffmpeg.exe -i amrwbencodedfile.amr pcmencodedfile.wav

## Background
IETF RFC4867 defines RTP payload formats and storage formats for AMR and AMR_WB codecs. The "bandwidth efficient" described in section 4.3 is used inside mobile core networks to convey codec frames using RTP. The storage format in section 5 is used for audio files encoded with AMR or AMR-WB codecs.

3GPP TS24.415 defines the framing protocol for user plane data used in the Iu interface (between MSC/SGSN and RNC). PDU Type 0 is the usual frame format used to convey AMR / AMR-WB codec frames.
