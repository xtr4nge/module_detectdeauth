#!/usr/bin/env python
'''
    Copyright (C) 2016 xtr4nge [_AT_] gmail.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

#REF: See more at: http://www.devx.com/security/Article/34741/0/page/5#sthash.fvgIZJVs.dpuf

# EXAMPLE DEAUTH
# BROADCAST: aireplay-ng -0 10 -a 00:24:33:xx:xx:xx mon0
# CLIENT: aireplay-ng -0 10 -a 00:24:33:xx:xx:xx -c 00:00:00:00:00:01 mon0


import datetime
a = datetime.datetime.now()

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy import *
from scapy.all import *

import time
import sys, getopt
import json
from multiprocessing import Process
import signal
import threading

# HELP MENU
def usage():
    print "\nscan-deauth 1.0 by xtr4nge"
    
    print "Usage: scan-deauth.py <options>\n"
    print "Options:"
    print "-i <i>, --interface=<i>                  set interface (default: mon0)"
    print "-t <time>, --time=<time>                 scan time"
    print "-l <log>, --log=<log>                    log file (output)"
    print "-d <seconds> --delay=<seconds>           seconds between alerts"
    print "-a --alert                               enables email alerts"
    print "-j --jump                                enables channel hopping"
    print "-n --number                              number of deauth pkt before delay to trigger the alert (default: 20)"
    print "-h                                       Print this help message."
    print ""
    print "Author: xtr4nge"
    print ""

# MENU OPTIONS
def parseOptions(argv):
    INTERFACE = "mon0"
    TIME =  int(0)
    LOG = ""
    MONITOR = ""
    CHANNEL = "1,2,3,4,5,6,7,8,9,10,11,12"
    FILE = ""
    DELAY = 5
    ALERT = False
    JUMP = False
    NUMBER = 20

    try:
        opts, args = getopt.getopt(argv, "hi:t:l:c:d:ajn:",
                                   ["help", "interface=", "time=", "log=", "channel=", "delay=", "alert", "jump", "number="])

        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit()
            elif opt in ("-i", "--interface"):
                INTERFACE = arg
            elif opt in ("-t", "--time"):
                TIME = int(arg)
            elif opt in ("-l", "--log"):
                LOG = arg
                with open(LOG, 'w') as f:
                    f.write("")
            elif opt in ("-c", "--channel"):
                CHANNEL = arg
            elif opt in ("-d", "--delay"):
                DELAY = arg
            elif opt in ("-a", "--alert"):
                ALERT = True
            elif opt in ("-j", "--jump"):
                JUMP = True
            elif opt in ("-n", "--number"):
                NUMBER = int(arg)
        
                
        # CHANNEL INTO INT ARRAY
        TEMP = CHANNEL.split(",")
        CHANNEL = []
        for i in TEMP:
            CHANNEL.append(int(i))
        
        return (INTERFACE, TIME, LOG, CHANNEL, DELAY, ALERT, JUMP, NUMBER)
                    
    except getopt.GetoptError:           
        usage()
        sys.exit(2) 

# CHECKS TIME PASSED BETWEEN ALERTS
def checkDelay(FLAG, DELAY):
    NOW = int(time.time())
    FLAG = int(FLAG)

    if (FLAG + DELAY) < NOW:
        return True
    else:
        return False

def logEvent(LOG, MSG):
    with open(LOG, 'a') as f:    
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        f.write(str(timestamp) +"," + MSG + "\n")

# SEND EMAIL ALERTS
def sendMail(MSG):
    global LOG
    
    import smtplib
    from configobj import ConfigObj
    config = ConfigObj("email.conf")
    
    FROM    = config["email"]["from"]
    TO      = config["email"]["to"]
    SUBJECT = "FruityWiFi ALERT: DetectDeauth"
    TEXT    = MSG
    SERVER  = config["email"]["server"]
    PORT    = config["email"]["port"]
    USER    = config["email"]["user"]
    PASS    = config["email"]["pass"]
    AUTH    = config["email"]["auth"]
    STLS    = config["email"]["starttls"]
    
    message = """\From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (FROM, TO, SUBJECT, TEXT)
        
    try:
        server = smtplib.SMTP(SERVER, PORT)
        if STLS == "1": server.starttls()
        if AUTH == "1": server.login(USER, PASS)
        server.sendmail(FROM, TO, message)
        server.quit()
    except:
        print "SMTP ERROR. (Fix the setup and restart the module.)"
        logEvent(LOG, "SMTP ERROR. (Fix the setup and restart the module.)")
        sys.exit(1)

# -------------------------
# GLOBAL VARIABLES
# -------------------------

(INTERFACE, TIME, LOG, CHANNEL, DELAY, ALERT, JUMP, NUMBER) = parseOptions(sys.argv[1:])

INVENTORY = {}
ROGUEDEAUTH = {}

# -------------------------
# SNIFFER
# -------------------------
def sniffer(p):
    
    b = datetime.datetime.now()
    
    # ---- MAGIC HERE ----
    
    if p.haslayer(Dot11Deauth) or p.haslayer(Dot11Disas):
        #print "MAC->"+p.addr1+"|"+p.addr2+"|"+p.addr3
        
        bssid = p.addr3
        
        if p.addr3 not in INVENTORY:
            MAC = {}
            INVENTORY[p.addr3] = [1, MAC, int(time.time())]
            key = str(p.addr1) + "|" + str(p.addr2)
            INVENTORY[p.addr3][1][key] = 1
            
        elif p.addr3 in INVENTORY and INVENTORY[p.addr3][0] < NUMBER: # NUMBER default 50
            key = str(p.addr1) + "|" + str(p.addr2)
            if checkDelay(INVENTORY[bssid][2], DELAY) == False: # COUNT DEAUTH++
                INVENTORY[p.addr3][0] += 1                
                if key in INVENTORY[p.addr3][1]:
                    INVENTORY[p.addr3][1][key] += 1
                else:
                    INVENTORY[p.addr3][1][key] = 1
            else: # RESET
                INVENTORY[p.addr3][0] = 1
                INVENTORY[bssid][2] = int(time.time())
                    
        else: # ALERT
            MAC = {}
            INVENTORY[p.addr3] = [1, MAC, int(time.time())]
            key = str(p.addr1) + "|" + str(p.addr2)
            INVENTORY[p.addr3][1][key] = 1
            
            if bssid not in ROGUEDEAUTH: # FIRST ALERT
                ROGUEDEAUTH[bssid] = int(time.time())
                print "DEAUTH: " + str(p.addr3) + " | [" + str(p.addr1) +"|"+ str(p.addr2)  + "] [NEW]"
                if LOG != "":
                    MSG = str(bssid) + "," + str(p.addr1) +"|"+ str(p.addr2) + " [NEW]"
                    logEvent(LOG, MSG)
                if ALERT:
                    sendMail("SSID: " + str(bssid) + "\nDETAILS: " + str(p.addr1) +"|"+ str(p.addr2))
                    print "EMAIL SENT."
                    if LOG != "": logEvent(LOG, "EMAIL SENT.")
                    
            elif checkDelay(ROGUEDEAUTH[bssid], DELAY): # FOLLOWING ALERT
                    ROGUEDEAUTH[bssid] = int(time.time())
                    print "DEAUTH: " + str(p.addr3) + " | [" + str(p.addr1) +"|"+ str(p.addr2) + "]"
                    if LOG != "":
                        MSG = str(p.addr3) + "," + str(p.addr1) +"|"+ str(p.addr2)
                        logEvent(LOG, MSG)

    # --------------------
    
    if (b - a) > datetime.timedelta(seconds=TIME) and TIME > 0:
        sys.exit()
        
    return

# Channel hopper - This code is very similar to that found in airoscapy.py (http://www.thesprawl.org/projects/airoscapy/)
def channel_hopper(interface):
    global CHANNEL
    while True:
        try:
            #channel = random.randrange(1,13)
            channel = random.choice(CHANNEL)
            os.system("iwconfig %s channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break

def stop_channel_hop(signal, frame):
    # set the stop_sniff variable to True to stop the sniffer
    global stop_sniff
    stop_sniff = True
    channel_hop.terminate()
    channel_hop.join()


try:
    if JUMP:
        channel_hop = Process(target = channel_hopper, args=(INTERFACE,))
        channel_hop.start()
        signal.signal(signal.SIGINT, stop_channel_hop)
    
    sniff(iface=INTERFACE, prn=sniffer, store=False, lfilter=lambda p: (Dot11Deauth in p or Dot11Disas in p))
    
except Exception as e:
    print str(e)
    print sys.exc_info()[0]
    print "Bye ;)"
