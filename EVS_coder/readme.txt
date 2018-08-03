====================================================================================
  EVS Codec 3GPP TS26.443 Nov 07, 2017. Version 12.9.0 / 13.5.0 / 14.1.0
====================================================================================

These files represent the 3GPP EVS Codec floating-point C simulation.  
All code is written in ANSI-C.  The system is implemented as two separate 
programs:

        EVS_cod   Encoder
        EVS_dec   Decoder
	
For encoding using the coder program, the input is a binary
audio file (*.8k, *.16k, *.32k, *.48k) and the output is a binary
encoded parameter file (*.192).  For decoding using the decoder program,
the input is a binary parameter file (*.192) and the output is a binary 
synthesized audio file (*.8k, *.16k, *.32k, *.48k).  


                            FILE FORMATS:
                            =============

The file format of the supplied binary data (*.8k, *.16k, *.32k, *.48k,
*.192) is 16-bit binary data which is read and written in 16 bit words.  
The data is therefore platform DEPENDENT.  
The files contain only data, i.e., there is no header.
The test files included in this package are "PC" format, meaning that the
least signification byte of the 16-bit word comes first in the files.

If the software is to be run on some other platform than PC,
such as an HP (HP-UX) or a Sun, then binary files will need to be modified
by swapping the byte order in the files.

The input and output files (*.8k, *.16k, *.32k, *.48k) are 16-bit signed
binary files with 8/16/32/48 kHz sampling rate with no headers.

The Encoder produces bitstream files in either ITU G.192 or MIME file
storage format.

Using ITU G.192 format:	

For every 20 ms input audio frame, the encoded bitstream contains the following data:

	Word16 SyncWord
	Word16 DataLen
	Word16 1st Databit
	Word16 2nd DataBit
	.
	.
	.
	Word16 Nth DataBit


The SyncWord from the encoder is always 0x6b21. If decoder receives SyncWord as 0x6b20
it indicates that the current frame was received in error (bad frame).

The DataLen parameter gives the number of audio data bits in the frame. For example using
DTX, DataLen for NO_DATA frames is zero.

Each bit is presented as follows: Bit 0 = 0x007f, Bit 1 = 0x0081.

Using MIME file storage format: 

The MIME file storage format is a byte based format which is
appropriate for media file storage or as format for email/MMS
attachments. 

Encoder: With the "-mime" option, the encoder always produces EVS-mime storage
format specified in TS26.445 Annex.2.6. The AMRWB-mime(RFC4867) storage
format is not supported by the encoder. 

Decoder: With the "-mime" option, the decoder can parse both EVS-mime
format storage files and AMRWB-mime (RFC4867) storage format files. 
The decoder automatically distinguishes between the two
mime storage formats by reading the initial Magic Word in the bitstream
file. The EVS-mime storage format is described in TS 26.445, Annex
A.2.6. The AMRWB-mime storage format is described in RFC-4867. 


			INSTALLING THE SOFTWARE
			=======================

Installing the software on the PC:

First unpack the compressed folder into your directory. After that you 
should have the following structure:

.
`-- c-code
    |-- Makefile
    |-- Workspace_msvc
    |-- lib_com
    |-- lib_dec
    |-- lib_enc
    `-- readme.txt

The package includes a Makefile for gcc, which has been verified on
32-bit Linux systems. The code can be compiled by entering the directory
"c-code" and typing the command: make. The resulting encoder/decoder
executables are named "EVS_cod" and "EVS_dec". Both reside in the c-code
directory.

The package also includes solution-file for Microsoft Visual
Studio 2008 (x86). To compile the code, please open
"Workspace_msvc\Workspace_msvc.sln", and build "evs_enc" for the encoder
and "evs_dec" for the decoder executable. The resulting encoder/decoder
executables are named "EVS_cod.exe" and "EVS_dec.exe". Both reside in the c-code
directory.


                       RUNNING THE SOFTWARE
                       ====================

The usage of the "EVS_cod" program is as follows:

   Usage:

   EVS_cod [Options] R Fs input_file bitstream_file

Mandatory parameters:
---------------------
R                : Bitrate in bps, 
                   for EVS native modes R = (5900*, 7200, 8000, 9600, 13200, 16400,
                                             24400, 32000, 48000, 64000, 96000, 128000) 
                                             *VBR mode (average bitrate),
                   for AMR-WB IO modes R =  (6600, 8850, 12650, 14250, 15850, 18250,
                                             19850, 23050, 23850) 
                   Alternatively, R can be a bitrate switching file which consits of R values
                   indicating the bitrate for each frame in bit/s. These values are stored in
                   binary format using 4 bytes per value
Fs               : Input sampling rate in kHz, Fs = (8, 16, 32 or 48) 
input_file       : Input signal filename (*.8k, *.16k, *.32k, *.48k)
bitstream_file   : Output bitstream filename (*.192)

Options:
--------
-q               : Quiet mode, no frame counters
                   default is deactivated
-dtx D           : Activate DTX mode, D = (0, 3-100) is the SID update rate
                   where 0 = adaptive, 3-100 = fixed in number of frames,
                   default is deactivated
-dtx             : Activate DTX mode with a SID update rate of 8 frames
-rf  p o         : Activate channel-aware mode for WB and SWB signal at 13.2kbps, 
                   where FEC indicator, p: LO or HI, and FEC offset, o: 2, 3, 5, or 7 in number of frames.
                   Alternatively p and o can be replaced by a rf configuration file with each line  
                   contains the values of p and o separated by a space, 
                   default is deactivated                  
-max_band B      : Activate bandwidth limitation, B = (NB, WB, SWB or FB)
                   alternatively, B can be a text file where each line contains
                   "nb_frames B"
-no_delay_cmp    : Turn off delay compensation
-mime            : Mime output bitstream file format
                   The encoder produces TS26.445 Annex.2.6 Mime Storage Format, (not RFC4867 Mime Format).
                   default output bitstream file format is G.192

The usage of the "EVS_dec" program is as follows:

   Usage:
   
   EVS_dec [Options] Fs bitstream_file output_file

Mandatory parameters:
---------------------
Fs                : Output sampling rate in kHz (8, 16, 32 or 48)
bitstream_file    : Input bitstream filename (*.192) or RTP packet filename (in VOIP mode)
output_file       : Output audio filename (*.8k, *.16k, *.32k, *.48k)

Options:
--------
-q               : Quiet mode, no frame counter
                   default is deactivated
-VOIP            : Activate VOIP mode
                   default is deactivated
-fec_cfg_file    : Optimal channel aware configuration computed by the JBM
				   as described in Section 6.3.1 of TS26.448. The output is
                   written into a .txt file. Each line contains the FER indicator
                   (HI|LO) and optimal FEC offset.				   
-Tracefile TF    : Generate trace file named TF (used only when -VOIP is activated)
-no_delay_cmp    : Turn off delay compensation
-mime            : Mime bitstream file format
                   The decoder may read both TS26.445 Annex.2.6 and RFC4867 Mime Storage
                   Format files, the magic word in the mime file is used to determine
                   which of the two supported formats is in use.
                   default bitstream file format is G.192


