################################################################################
#
# Copyright (c) 2011, Jakob Thomsen, marama.dk
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
#    Wireshark for sniffing of IEEE802.15.4 and Zigbee frames.
#
#    The wrapper adds a libpcap message header to IEEE802.15.4 MSDU's
#    to allow the messages to be interpreted by Wireshark
#
###############################################################################
#
# $Id$ 
# $Date$   
# $Rev$
# $LastChangedBy$
#
###############################################################################

#import logging
import struct, serial, time, binascii
import os
if(os.name == 'nt'):
        import win32pipe, win32file

DLT_IEEE802_15_4    = 195
TCPDUMP_MAGIC       = 0xa1b2c3d4 # Standard libpcap format
PCAP_VERSION_MAJOR  = 2
PCAP_VERSION_MINOR  = 4

MICROS_PER_SYMBOL   = 16 # symbol duration in us

class cWS_IEEE802_15_4_LibPcapWrapper:
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
        
    def WriteFileHeader(self):
        if(self.os == 'nt'):
            win32file.WriteFile(self.p, struct.pack("<L",TCPDUMP_MAGIC))
            win32file.WriteFile(self.p, struct.pack("<H",PCAP_VERSION_MAJOR))
            win32file.WriteFile(self.p, struct.pack("<H",PCAP_VERSION_MINOR))
    
            win32file.WriteFile(self.p, struct.pack("<L",0)) # u32Thiszone: gmt to local correction
            win32file.WriteFile(self.p, struct.pack("<L",0)) # u32Sigfigs: accuracy of time stamps
            win32file.WriteFile(self.p, struct.pack("<L",200)) # u32Snaplen: max length saved portion of each pkt
            win32file.WriteFile(self.p, struct.pack("<L",DLT_IEEE802_15_4)) # u32LinkType: data link type (LINKTYPE_*) 

        elif(self.os == 'posix'):
            os.write(self.p, struct.pack("<L",TCPDUMP_MAGIC))
            os.write(self.p, struct.pack("<H",PCAP_VERSION_MAJOR))
            os.write(self.p, struct.pack("<H",PCAP_VERSION_MINOR))
            
            os.write(self.p, struct.pack("<L",0)) # u32Thiszone: gmt to local correction
            os.write(self.p, struct.pack("<L",0)) # u32Sigfigs: accuracy of time stamps
            os.write(self.p, struct.pack("<L",200)) # u32Snaplen: max length saved portion of each pkt
            os.write(self.p, struct.pack("<L",DLT_IEEE802_15_4)) # u32LinkType: data link type (LINKTYPE_*) 
    
    def WriteRecord(self, snifferDataFrm, channel):
        pktLen = snifferDataFrm.getMsduLen()
        timeStamp = MICROS_PER_SYMBOL * snifferDataFrm.getTimeStamp()
    
        i32Secs = timeStamp // 1000000
        i32MicroSecs = timeStamp % 1000000

        if(self.os == 'nt'): 
            win32file.WriteFile(self.p, struct.pack("<l",i32Secs)) # seconds
            win32file.WriteFile(self.p, struct.pack("<l",i32MicroSecs)) # microseconds
        
            # length of portion present
            win32file.WriteFile(self.p, struct.pack("<L",pktLen)) # u32
        
            # length this packet (off wire)
            win32file.WriteFile(self.p, struct.pack("<L",pktLen+2)) # u32
    
            # Record data
            win32file.WriteFile(self.p, snifferDataFrm.getMsdu())
            #print binascii.hexlify(snifferDataFrm.getMsdu())

        elif(self.os == 'posix'):
            os.write(self.p, struct.pack("<l",i32Secs)) # seconds
            os.write(self.p, struct.pack("<l",i32MicroSecs)) # microseconds
        
            # length of portion present
            os.write(self.p, struct.pack("<L",pktLen)) # u32
        
            # length this packet (off wire)
            os.write(self.p, struct.pack("<L",pktLen+2)) # u32
    
            # Record data
            os.write(self.p, snifferDataFrm.getMsdu())
            #print binascii.hexlify(snifferDataFrm.getMsdu())
