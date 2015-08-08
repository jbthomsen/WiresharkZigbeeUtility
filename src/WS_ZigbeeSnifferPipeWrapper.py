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
#    This file implements a very simple adapter for a Freescale 1322x USB 
#    Dongle/Zniffer (IEEE802.15.4 sniffer device via USB / virtual serial port).
#    The cWS_SnifferWrapperMC1322x facilitates basic configuration of the 
#    sniffer device and enables receipt of frames captured by the device.
#
###############################################################################
#
# $Id$ 
# $Date$   
# $Rev$
# $LastChangedBy$
#
###############################################################################

"""Create a named pipe between Wireshark and a Freescale 1322x USB dongle zniffer.

Usage: WS_ZigbeeSnifferPipeWrapper <parameters>

Parameters:
    -h / --help
        Print this message and exit.
        
    --port=serialPort
        Specify the serial port for the sniffer device, e.g. --port=COM8
        
    --channel=channel
        Specify the channel to listen to, e.g. --channel=14

    --encap
        Specify the pcap encapsulation, 802.15.4 (default) or zepv1

    --scan
        Scan channels 11..26 starting from the one specified by --channel

    --scan-interval
        The interval, in seconds, to listen to every channel (default 30)

    --scan-lock
        Stop scanning after capturing the first packet 
"""

import WS_SnifferAdapterFreescale
import WS_SnifferLibPcapWrapper
import WS_SnifferLibPcapZepWrapper
import getopt, sys #, traceback
from serial import SerialException
import time
#import binascii

def usage(code, msg=''):
    print >> sys.stderr, __doc__
    if msg:
        print >> sys.stderr, msg
    sys.exit(code)


def main():
    sPort = None # "COM8"
    channel = None # 14
    before = None
    scan = False
    scanInterval = 30 * 1000 # 30s
    scanLock = False
    
    ENCAP = ["802.15.4", "zepv1"]
    encap = ENCAP[0]

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hv", ["help", "port=", "channel=", "encap=", "scan", "scan-interval=", "scan-lock", "verbose"])
        
    except getopt.GetoptError, err:
        # print help information and exit:
        print str(err)
        usage("")
        sys.exit(2)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage("")
            sys.exit()
        elif o in ("--port"):
            sPort = a
        elif o in ("--channel"):
            channel = int(a)
        elif o in ("--encap"):
            encap = a
        elif o in ("--scan"):
            scan = True
        elif o in ("--scan-interval"):
            scanInterval = int(a) * 1000
        elif o in ("--scan-lock"):
            scanLock = True
        else:
            assert False, "unhandled option"

    if (sPort is None) or (channel is None):
        usage("You must specify both serial port and channel, e.g.\n\n%s --port=COM8 --channel=14" % sys.argv[0])
        sys.exit()

    if (not encap in ENCAP):
        usage("Unsupported encapsulation %s" % encap)
        sys.exit()

    if (scan):
        print "Scanning channels 11..26 starting from channel %d" % channel

    pipeWrapper = None
    try:
        # Connect to Zigbee sniffer device
        print "Configuring sniffer on port '%s' to listen on channel %d" % (sPort, channel)
        snifferAdapter = WS_SnifferAdapterFreescale.cWS_SnifferWrapperMC1322x(sPort, channel)
        
        # Open named pipe to Wireshark
        if (encap == ENCAP[0]): 
            pipeWrapper = WS_SnifferLibPcapWrapper.cWS_IEEE802_15_4_LibPcapWrapper()
        elif (encap == ENCAP[1]):
            pipeWrapper = WS_SnifferLibPcapZepWrapper.cWS_ZEPv1_LibPcapWrapper()

        print "Configure Wireshark to listen to the name pipe '%s'" % (pipeWrapper.getPipeName())
        pipeWrapper.OpenPipe()
        
        # Write libpcap file header to pipe
        pipeWrapper.WriteFileHeader()
        
        i = 0
        while 1:
            dataFrm = snifferAdapter.RcvDataFrame()
            if not dataFrm is None:
                #print "[%d,%d,%d,%d]: %s" %(i, dataFrm.getTimeStamp(), dataFrm.getLinkQuality(), dataFrm.getMsduLen(), binascii.hexlify(dataFrm.getMsdu()))
                i = i + 1
                sys.stdout.write("%d\r" % i)
                sys.stdout.flush()
                pipeWrapper.WriteRecord(dataFrm, channel)

            lock = not scan or (i > 0 and scanLock)
            if (not lock):
                now = time.time() * 1000.0
                if (before == None):
                    before = now
                if ((now - before) >= scanInterval):
                    before = now
                    channel += 1
                    if (channel > 26):
                        channel = 11
                    snifferAdapter.ChangeLogicalChannel(channel)
                    print "Changed to channel %d" % channel
                
    except SerialException, err:
        sys.stderr.write('ERROR: %s\n' % str(err))
        sys.stderr.flush();
        #traceback.print_exc()

    # For now: assume pipe closed
    except Exception, err:
        if not pipeWrapper is None:
            print "Pipe '%s' closed by Wireshark" % (pipeWrapper.getPipeName())
            pipeWrapper.ClosePipe()

    except KeyboardInterrupt:
        if not pipeWrapper is None:
            print " Caught"
            pipeWrapper.ClosePipe()

if __name__ == "__main__":
    main()
