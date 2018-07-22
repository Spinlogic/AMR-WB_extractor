# AMR-WB Extractor
Extracts AMR-WB frames from RTP inside PCAP files and builds a .amr-wb file that complies with the storage format in RFC4867.

## Dependencies
These scripts require the latest versions of [scapy](https://github.com/secdev/scapy) and [bitarray](https://pypi.org/project/bitarray/).

## Usage
>python pcap_parser.py -i <_rtpfilteredpcap_> -o <_outputamrwbencodedaudio_>

>python pcap_parser_iu.py -i <_rtpfilteredpcap_> -o <_outputamrwbencodedaudio_>

where:

* **rtpfilteredpcap** must be a pcap or pcapng file filtered to include only RTP data. In principle, it should contain only the RTP flow that you want to extract into an audio file for listening on your PC.
* **outputamrwbencodedaudio** is the name of the output file with the extracted AMR-WB audio.

**pcap_parser.py** use this script if the AMR-WB data inside the RTP is encapsulated in "bandwidth efficient" mode as described in RFC4867.

**pcap_parser_iu.py** use this script if the AMR-WB data inside the RTP is encapsulated using the Iu framing protocol (refer to 3GPP TS25.415).

## Tools
Due to license issues, there are few media players out there that can play AMR-WB encoded audio files. However, the latest versions of [ffmpeg](https://ffmpeg.org/) support this codec and can be used to convert AMR-WB audio to PCM audio with the following command:

>ffmpeg.exe -i amrwbencodedfile.amr-wb pcmencodedfile.wav

## Background
IETF RFC4867 defines RTP payload formats and storage formats for AMR and AMR_WB codecs. The "bandwidth efficient" described in section 4.3 is used mobile networks to convey codec frames using RTP. The storage format in section 5 is used for audio files encoded with AMR or AMR-WB codecs.

3GPP TS24.415 defines the framing protocol for user plane data used in the Iu interface (between MSC/SGSN and RNC).

