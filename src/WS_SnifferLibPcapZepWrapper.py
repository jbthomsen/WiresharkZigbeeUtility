################################################################################
#
# Copyright (c) 2011, Jakob Thomsen, marama.dk
#                     Cristiano De Alti
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of MARAMA nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY MARAMA ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL MARAMA BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
###############################################################################
# 
# Description : 
#    This file implements a very simple libpcap file wrapper for easy 
#    creation of a named pipe to be used as an alternative input for 
#    Wireshark for sniffing of IEEE802.15.4, Zigbee and 6LoWPAN frames.
#
#    The wrapper encapsulates the IEEE 802.15.4 Packet in a ZEPv1 Packet
#    to allow the messages to be interpreted by Wireshark.
#    ZEP encapsulation contains information about the RSSI and the channel
#    of the received packet. The latter may be useful if the sniffer
#    is configured to scan a list of channels.
#
# [1] https://wiki.wireshark.org/IEEE_802.15.4
# [2] http://anonsvn.wireshark.org/wireshark/trunk/epan/dissectors/packet-zep.c
###############################################################################
#
# $Id$ 
# $Date$   
# $Rev$
# $LastChangedBy$
#
###############################################################################

#import logging
import struct, serial, time, binascii, socket, ctypes
import os
if(os.name == 'nt'):
        import win32pipe, win32file

DLT_IPV4            = 228 # Raw IPv4
TCPDUMP_MAGIC       = 0xa1b2c3d4 # Standard libpcap format
PCAP_VERSION_MAJOR  = 2
PCAP_VERSION_MINOR  = 4

 #------------------------------------------------------------
 #
 #      ZEP Packets must be received in the following format:
 #      |UDP Header|  ZEP Header |IEEE 802.15.4 Packet|
 #      | 8 bytes  | 16/32 bytes |    <= 127 bytes    |
 #------------------------------------------------------------
 #
 #      ZEP v1 Header will have the following format:
 #      |Preamble|Version|Channel ID|Device ID|CRC/LQI Mode|LQI Val|Reserved|Length|
 #      |2 bytes |1 byte |  1 byte  | 2 bytes |   1 byte   |1 byte |7 bytes |1 byte|
 #
 #      ZEP v2 Header will have the following format (if type=1/Data):
 #      |Preamble|Version| Type |Channel ID|Device ID|CRC/LQI Mode|LQI Val|NTP Timestamp|Sequence#|Reserved|Length|
 #      |2 bytes |1 byte |1 byte|  1 byte  | 2 bytes |   1 byte   |1 byte |   8 bytes   | 4 bytes |10 bytes|1 byte|
 #
 #      ZEP v2 Header will have the following format (if type=2/Ack):
 #      |Preamble|Version| Type |Sequence#|
 #      |2 bytes |1 byte |1 byte| 4 bytes |
 #------------------------------------------------------------

ZEP_DEFAULT_PORT    = 17754
ZEP_PREAMBLE        = "EX"
ZEP_V1              = 1

# To avoid computing the IPv4 header checksum for every capture
# we consider a max length 802.15.4 PSDU.
# Then we limit the capture length in the PCAP Packet Header
PKT_LEN_MAX = 127 # max length of an 802.15.4 PSDU
ZEPV1_HDR_LEN = 16
UDP_LEN_MAX = ZEPV1_HDR_LEN + PKT_LEN_MAX + 8
IPV4_LEN_MAX = UDP_LEN_MAX + 20 # 171 bytes
IPV4_HDR_CHK = 0x3c40 # pre-computed header checksum for a max length PSDU

MICROS_PER_SYMBOL   = 16 # symbol duration in us

class cWS_ZEPv1_LibPcapWrapper:

    # pre-compiled headers
    s = struct.Struct("<L 2H 4L")
    pcapGlobalHdr = s.pack(TCPDUMP_MAGIC,
                           PCAP_VERSION_MAJOR,
                           PCAP_VERSION_MINOR,
                           0, # u32Thiszone: gmt to local correction
                           0, # u32Sigfigs: accuracy of time stamps
                           65535, # u32Snaplen: max length saved portion of each pkt
                           DLT_IPV4) # u32LinkType: data link type (LINKTYPE_*)

    structPcapPktHdr = struct.Struct("<2l 2L")

    s = struct.Struct("!2B 3H 2B H 4s 4s")
    ipv4Hdr = s.pack(0x45, # Version + IHL
                     0x00, # TOS
                     IPV4_LEN_MAX,
                     0x0000, # Identification
                     0x4000, # Don't fragment + offset
                     64, # TTL
                     17, # Protocol: UDP
                     IPV4_HDR_CHK,
                     socket.inet_aton("127.0.0.1"), # Source
                     socket.inet_aton("127.0.0.1")) # Dest

    s = struct.Struct("!4H")
    udpHdr = s.pack(0x0000, # Source port optional (zero)
                    ZEP_DEFAULT_PORT,
                    UDP_LEN_MAX,
                    0x0000) # UDP checksum optional (zero)

    structZep = struct.Struct("!2s 2B H 2B 7s B")

    @staticmethod
    def GetPcapPktHdr(timestamp, captureLen):
        s = cWS_ZEPv1_LibPcapWrapper.structPcapPktHdr

        ts = MICROS_PER_SYMBOL * timestamp
    
        i32Secs = ts // 1000000
        i32MicroSecs = ts % 1000000

        return s.pack(i32Secs, # seconds
                      i32MicroSecs, # microseconds
                      captureLen, # u32
                      IPV4_LEN_MAX) # u32

    @staticmethod
    def GetZepHdr(ch, pduLen, lqi):
        s = cWS_ZEPv1_LibPcapWrapper.structZep
        return s.pack(ZEP_PREAMBLE,
                      ZEP_V1,
                      ch,
                      0x0000, # Device ID
                      0, # LQI mode
                      lqi,
                      "\x00\x00\x00\x00\x00\x00\x00", # Reserved
                      pduLen)

    def __init__(self):
        self.os = os.name

        if(self.os == 'nt'):
            self.sPipeName = r'\\.\pipe\wireshark'
        elif(self.os == 'posix'):
            self.sPipeName = r'/tmp/wireshark'
            self.f = -1

        self.p = None
        
    def OpenPipe(self):#,pipeName = r'\\.\pipe\wireshark'):
        #self.sPipeName = pipeName
        if(self.os == 'nt'):
            self.p = win32pipe.CreateNamedPipe(
                self.sPipeName,
                win32pipe.PIPE_ACCESS_OUTBOUND,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
                1, 65536, 65536,
                300,
                None)
            win32pipe.ConnectNamedPipe(self.p, None)
        elif(self.os == 'posix'):
            os.mkfifo(self.sPipeName)
            self.f = 0 #Remember to unlink the FIFO
            self.p = os.open(self.sPipeName, os.O_WRONLY)
        
    def ClosePipe(self):
        if not self.p is None:
            if(self.os == 'nt'):
                win32pipe.DisconnectNamedPipe(self.p)
            elif(self.os == 'posix'):
                os.close(self.p)

        if(self.os == 'posix' and self.f == 0):
            os.unlink(self.sPipeName)
        
    def getPipeName(self):
        return self.sPipeName

    def WritePipe(self, s):
        if(self.os == 'nt'):
            win32file.WriteFile(self.p, s)
        elif(self.os == 'posix'):
            os.write(self.p, s)
        
    def WriteFileHeader(self):
        self.WritePipe(cWS_ZEPv1_LibPcapWrapper.pcapGlobalHdr)

    def WriteRecord(self, snifferDataFrm, channel):
        timestamp = snifferDataFrm.getTimeStamp()
        pktLen = snifferDataFrm.getMsduLen()
        pktLen += 2 # ZEP requires a full PDU with the two FCS octets
        lqi = snifferDataFrm.getLinkQuality()
        rssi = (lqi // 3) - 100 # dBm
        # limit the length of capture to the actual PSDU length
        pcapInclLen = IPV4_LEN_MAX - PKT_LEN_MAX + pktLen

        # PCAP packet header
        pcapPktHdr = cWS_ZEPv1_LibPcapWrapper.GetPcapPktHdr(timestamp,
                                                            pcapInclLen)
        self.WritePipe(pcapPktHdr)
    
        # IPv4 header
        self.WritePipe(cWS_ZEPv1_LibPcapWrapper.ipv4Hdr)

        # UDP header
        self.WritePipe(cWS_ZEPv1_LibPcapWrapper.udpHdr)

        # ZEP header
        self.WritePipe(cWS_ZEPv1_LibPcapWrapper.GetZepHdr(channel, pktLen, lqi))

        # Record data
        self.WritePipe(snifferDataFrm.getMsdu())
        self.WritePipe(struct.pack("!b B",
                                   rssi, # RSSI in dBm (Chipcon format)
                                   0x80 | 0x00)) # FCS valid bit + correlation (Chipcon format)

        #print binascii.hexlify(snifferDataFrm.getMsdu())
