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
#    This file implements a very simple wrapper for a Freescale 1322x USB 
#    Dongle/Zniffer (IEEE802.15.4 sniffer device via USB / virtual serial port).
#    The cWS_SnifferWrapperMC1322x facilitates easy configuration of the 
#    sniffer device and enables basic receipt of frames captured by the device.
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

ZTC_STATUS_OK = 0
ZTC_STX = 0x02

# ZTC Frame format
#
# Byte:     0   1   2         (3..n+3)
#         +---+---+---+------- . . . -------+
#         !   !   !   !                     !
#         +---+---+---+------- . . . -------+
# Length:   1   1   1          n
#
#
# Byte 0: Opcode group
# Byte 1: Opcode
# Byte 2: Length of data field (excluding header)
# Byte 3 to (n+3): Data, including time stamps where applicable
#
class cZtcFrame:
    """ TBD
    """
#==============================================================================
    #def __init__(self, binFrm = None):
    #    self.binFrm = binFrm

    def __init__(self, OpCodeGrp, OpCode, Length, binPayload):
        self.binFrm = struct.pack("<BBB", OpCodeGrp, OpCode, Length) + binPayload
    
    def getBinFrm(self):
        return self.binFrm
    
    def getHdr(self):
        """ returns header data in the form (OpCodeGrp, OpCode, Length) """
        return struct.unpack("<BBB",self.binFrm[0:3])
    
    def getPayloadLen(self):
        return ord(self.binFrm[2])
    
    def getBinPayload(self):
        return self.binFrm[3:]

    def getStatus(self):
        return ord(self.binFrm[3])

    def getFCS(self):
        crc = 0
        for b in self.binFrm:
            crc ^= ord(b)
        return crc
        
        
# Promiscuous mode sniffer frame format
#
# Header        [2 bytes] = 86 03
# PayloadLength [1 byte ] 
# LinkQuality   [1 byte ] 
# TimeStamp     [4 bytes] 
# msduLength    [1 byte ] 
# msdu          [n bytes]
class cSnifferDataFrm(cZtcFrame):
    #def __init__(self, binFrm = None):
    #    cZtcFrame.__init__(self, binFrm)

    def __init__(self, OpCodeGrp, OpCode, Length, binPayload):
        cZtcFrame.__init__(self,OpCodeGrp, OpCode, Length, binPayload)

    def getLinkQuality(self):
        return ord(self.binFrm[3])
    
    def getTimeStamp(self):
        return struct.unpack("<L",self.binFrm[4:8])[0]
    
    def getMsduLen(self):
        return struct.unpack("<B",self.binFrm[8:9])[0]
    
    def getMsdu(self):
        return self.binFrm[9:]

class cWS_SnifferWrapperMC1322x:
    """ TBD """
#==============================================================================
    def __init__(self, sPort, defaultChannel, fRxTimeout=3.0):
        self.s = serial.Serial(port=sPort, baudrate=921600,  timeout=fRxTimeout) #,  bytesize=serial.EIGHTBITS,  parity=serial.PARITY_NONE,  stopbits=serial.STOPBITS_ONE
        self.channel = defaultChannel
        self.Reset()

    def rcvStx(self):
        stxByte = self.s.read(1)
        if len(stxByte) == 0:
            return 0
         
        stx = ord(stxByte)
        assert stx == ZTC_STX, "getStx: Got 0x%x instead of STX (0x02) delimiter" % stx
        return 1

    def Reset(self):
        self.ResetSnifferCPU()
        self.SetSnifferMode()
        self.SetRxOnWhenidle(0)
        self.SetLogicalChannel(self.channel)
        self.SetMacPromiscuousMode()
        self.SetRxOnWhenidle(1)
        
    def ChangeLogicalChannel(self, channel):
        self.channel = channel
        self.Reset()

    def RcvFrame(self):
        if self.rcvStx() == 0:
            return None
        
        opCodeGrp = ord(self.s.read(1))
        opCode = ord(self.s.read(1))
        payloadLen = ord(self.s.read(1))
        payload = self.s.read(payloadLen)
        
        fcs = ord(self.s.read(1))
        frm = cZtcFrame(opCodeGrp,opCode,payloadLen,payload)
        assert fcs == frm.getFCS(), "RcvFrame got unexpected FCS 0x%x, expected 0x%x" % (fcs,frm.getFCS()) 
        
        return frm
    
    def RcvDataFrame(self):
        if self.rcvStx() == 0:
            return None

        opCodeGrp = ord(self.s.read(1))
        opCode = ord(self.s.read(1))
        payloadLen = ord(self.s.read(1))
        payload = self.s.read(payloadLen)

        fcs = ord(self.s.read(1))
        dataFrm = cSnifferDataFrm(opCodeGrp,opCode,payloadLen,payload)
        assert fcs == dataFrm.getFCS(), "RcvDataFrame got unexpected FCS 0x%x, expected 0x%x" % (fcs,dataFrm.getFCS()) 

        return dataFrm 
    
    def SendFrm(self, frm):
        self.s.write(chr(ZTC_STX)) # Frame delimiter - start
        self.s.write(frm.getBinFrm())
        self.s.write(chr(frm.getFCS())) # Frame delimiter - stop

    def SetSnifferMode(self):
        ZtcModeSelectSnifferReq = cZtcFrame(0xA3,0x00,0x0A, struct.pack("<BBBBBBBBBB",1,1,1,0,0,0,0,0,0,0))
        self.SendFrm(ZtcModeSelectSnifferReq)
        cnfFrm = self.RcvFrame()
        assert cnfFrm.getStatus() == ZTC_STATUS_OK, "SetSnifferMode confirmation unsuccessful"

    def SetRxOnWhenidle(self, on):
        ZtcMacRxOnWhenIdleReq = cZtcFrame(0x85,0x09,0x08, struct.pack("<BBBBBBBB",0x52,on,0,0,0,0,0,0))
        self.SendFrm(ZtcMacRxOnWhenIdleReq)
        cnfFrm = self.RcvFrame()
        assert cnfFrm.getStatus() == ZTC_STATUS_OK, "SetRxOnWhenidle(%d) confirmation unsuccessful" % on
    
    def SetLogicalChannel(self, channel):
        ZtcMacLogicalChannelReq = cZtcFrame(0x85,0x09,0x08, struct.pack("<BBBBBBBB",0x21,channel,0x00,0x00,0x00,0x00,0x00,0x00))
        self.SendFrm(ZtcMacLogicalChannelReq)
        cnfFrm = self.RcvFrame()
        assert cnfFrm.getStatus() == ZTC_STATUS_OK, "SetLogicalChannel(%d) confirmation unsuccessful" % channel
        
    def SetMacPromiscuousMode(self):
        ZtcMacPromiscuousModeReq = cZtcFrame(0x85,0x09,0x08, struct.pack("<BBBBBBBB",0x51,0x01,0x00,0x00,0x00,0x00,0x00,0x00))
        self.SendFrm(ZtcMacPromiscuousModeReq)
        cnfFrm = self.RcvFrame()
        assert cnfFrm.getStatus() == ZTC_STATUS_OK, "SetMacPromiscuousMode confirmation unsuccessful"
    
    def ResetSnifferCPU(self):
        ZtcCpuResetReq = cZtcFrame(0xA3,0x08,0x00, "") 
        self.SendFrm(ZtcCpuResetReq)
        time.sleep(1.0)
        self.s.flushInput()


#snifferAdapter = cWS_SnifferWrapperMC1322x("COM8", 0x0e)
#
#for i in range(10):
#    dataFrm = snifferAdapter.RcvDataFrame()
#    if not dataFrm is None:
#        print "[%d,%d,%d,%d]: %s" %(i, dataFrm.getTimeStamp(), dataFrm.getLinkQuality(), dataFrm.getMsduLen(), binascii.hexlify(dataFrm.getMsdu()))
    
