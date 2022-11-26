#!/usr/bin/env python3

import struct
import hid
from binascii import hexlify,unhexlify

#https://github.com/merbanan/rfid_app/
#https://www.digchip.com/datasheets/parts/datasheet/147/EM4100-pdf.php
#http://ww1.microchip.com/downloads/en/DeviceDoc/ATA5577C-Read-Write-LF-RFID-IDIC-100-to-150-kHz-Data-Sheet-DS70005357B.pdf
#https://www.emmicroelectronic.com/sites/default/files/products/datasheets/4205-4305-DS-01.pdf

########### This is all cruft from the previous code ############
COMMAND_IDX = {
  0x00:"GetSupport",
  0x01:"TestDevice",
  0x03:"Buzzer",
  0x10:"Em4100read",
  0x12:"T5577",
  0x13:"Em4305",
  0x14:"Carrier",
# 0x20:"mifare_reset",
}


CMD_GET_SUPPORT = b'\x00'
CMD_TEST_DEVICE = b'\x01'
CMD_CMDTWO      = b'\x02'
CMD_BELL        = b'\x03'
CMD_EM4100_READ = b'\x10'
CMD_T5577       = b'\x12'
CMD_EM4305      = b'\x13'
CMD_CARRIER     = b'\x14' # takes arg 0=4


CMD_UNK_40    = b'\x40'
CMD_UNK_41    = b'\x41'
CMD_UNK_42    = b'\x42'
CMD_UNK_43    = b'\x43'

CMD_UNK_50    = b'\x50' #returns tag type
CMD_UNK_51    = b'\x51'
CMD_UNK_52    = b'\x52'
CMD_UNK_54    = b'\x54'


CMD_UNK_80    = b'\x80'
CMD_UNK_81    = b'\x81'
CMD_UNK_82    = b'\x82'
CMD_UNK_83    = b'\x83'

CMD_UNK_90    = b'\x90' #returns tag type
CMD_UNK_91    = b'\x91'
CMD_UNK_92    = b'\x92'
CMD_UNK_94    = b'\x94'

CMD_UNK_c0    = b'\xc0'
CMD_UNK_c1    = b'\xc1'
CMD_UNK_c2    = b'\xc2'
CMD_UNK_c3    = b'\xc3'

CMD_UNK_d0    = b'\xd0' #returns tag type
CMD_UNK_d1    = b'\xd1'
CMD_UNK_d2    = b'\xd2'
CMD_UNK_d4    = b'\xd4'


T5577_CMD_START=b'\x00'
T5577_CMD_UNK1=b'\x01'
T5577_CMD_FINAL=b'\x02'
T5577_CMD_UNK2=b'\x03'
T5577_CMD_WRITE_BLOCK=b'\x04'

EM4305_CMD_LOGIN=b'\x02'



RESPONSE_BYTE = b'\x92'
RESPONSE_WORD = b'\x93'
RESPONSE_DWORD = b'\x80'
RESPONSE_TAG = b'\x90'
RESPONSE_ERROR = b'\xff'

################ Kept around to compare with "OEM" software ###########

######### My code ########
##########################

#
# Class to deal with responses.
# It appears this wasn't entirely
# Necessary as Messages are just
# prefixed with a direction byte.
#
class Rsp():
  RESPONSE_OK = b'\x83'
  __pkt = b''
  def __init__(self, msg, expected=b'\x83'):
    self.__pkt = msg
    self.__expect = expected

  def RspLen(self):
    return self.__pkt[1]

  def GetRsp(self):
    return self.__pkt

  def IsResponseOK(self):
    m = Msg.fromMsg(self.__pkt)
    if m.IsChksumGood(self.__pkt[-2]):
      if self.__pkt[2:3] == self.__expect:
        return True
    return False

  def Display(self):
    print('[RESP]',end='')
    if len(self.__pkt)>0:
      for i in range(len(self.__pkt)):
        if i%8 == 0:
          print('')
        print(hexlify(self.__pkt[i:i+1]).decode('utf-8')+' ',end='')
    print('')
    print(self.IsResponseOK())

#
# Class to build messages based on
# what the software appears to do.
#
class Msg():
  __pkt = b''
  MESSAGE_END_MARKER = b'\x04'
  MESSAGE_START_MARKER = b'\x01'
  def __init__(self, cmd, parms):
    self.__pkt = self.__build_packet(cmd,parms)

  @classmethod
  def fromMsg(cls, msg):
    if isinstance(msg, bytes):
      return cls(msg[2:2+1],msg[3:-2])

  def Display(self):
    print('[MSG]',end='')
    if len(self.__pkt)>0:
      for i in range(len(self.__pkt)):
        if i%8 == 0:
          print('')
        print(hexlify(self.__pkt[i:i+1]).decode('utf-8')+' ',end='')
    print('')

  def GetMsg(self):
    return self.__pkt

  def __build_packet(self, command, parms):
    pkt = self.MESSAGE_START_MARKER
    if isinstance(command, int):
      cmd = command.to_bytes(1,'big')
    else:
      cmd = command
    pkt = pkt + (len(parms)+5).to_bytes(1,'big') + cmd
    for i in range(len(parms)):
      pkt = pkt + parms[i:i+1]
    pkt = pkt + self.__calc_checksum(pkt,len(pkt)) + self.MESSAGE_END_MARKER
    return pkt
  
  def __calc_checksum(self,buf, l):
    crc = 0
    for i in range(l):
      crc = crc^buf[i]
    return crc.to_bytes(1,'big')

  def GetChecksum(self):
    if len(self.__pkt) > 2:
      return self.__pkt[-2]
    else:
      return -1

  def IsChksumGood(self, chksm):
    if len(self.__pkt) > 2:
      cksm = self.__calc_checksum(self.__pkt, len(self.__pkt)-2)
      if chksm.to_bytes(1,'big') == cksm:
        return True
    return False

#
# Class that talks to the CTX-203-ID-RW
#
class CTX_IDRW203():
  CLIENT_TO_DEVICE_MARKER = b'\x03'
  DEVICE_TO_CLIENT_MARKER = b'\x05'
  def __init__(self, vid=0x6688, pid=0x6850, debug=False):
    self.__vid = vid
    self.__pid = pid
    self.__debug = debug
    self.__connected = False

  def IsDebugEnabled(self):
    return self.__debug

  def __dbg_msg(self, msg):
    if self.__debug == True:
      print('[DEBUG] '+msg)

  def IsConnected(self):
    return self.__connected

  def Connect(self):
    if not self.IsConnected():
      try:
        self.__dev = hid.Device(vid=self.__vid, pid=self.__pid)
        self.__dbg_msg('Device connected')
        self.__connected = True
      except:
        self.__dbg_msg('Device connection error')

  def Disconnect(self):
    if self.IsConnected():
      self.__dev.close()
      self.__dbg_msg('Device disconnected')
      self.__connected = False

  def SendMsg(self,msg):
    if isinstance(msg, Msg) and self.IsConnected():
      self.__dev.write(self.CLIENT_TO_DEVICE_MARKER+msg.GetMsg())
      self.__dbg_msg('Message sent')

  def __display_data(self,data):
    if self.__debug == True:
      print('[DATA]',end='')
      for i in range(len(data)):
        if i % 8==0:
          print('')
        print(hexlify(data[i:i+1]).decode('utf-8')+' ',end='')
      print('')

  def RecvRsp(self,exp=Rsp.RESPONSE_OK,raw_display=False):
    m= self.__dev.read(256)
    if raw_display:
      self.__display_data(m)
    if len(m) > 0:
      if m[0:1] == self.DEVICE_TO_CLIENT_MARKER:
        self.__dbg_msg('Response received')
        return Rsp(m[1:m[2]+1],expected=exp)
    return Rsp(b'')

################### MAIN ######################
##################        #####################

##############################################################
#
# cmd_test_noconnect: Attempts to build and send a command.
#
##############################################################
def cmd_test_noconnect(cmd, arg=b'', d=None):
  if d == None:
    print('No device specified in parameters!')
    return
  ### Create message ###
  m = Msg(cmd, arg)
  if d.IsDebugEnabled():
    m.Display()
    print(m.GetChecksum())
    print(m.IsChksumGood(m.GetChecksum()))
  ### Let's send it ###
  d.SendMsg(m)
  r = d.RecvRsp()
  r.Display()
  return r

##############################################################
#
# cmd_test: Attempts to build and send a command.  Connects
#           and disconnects every time.  Not really useful.
#
##############################################################
def cmd_test(cmd, arg=b''):
  ### Connect ###
  d = CTX_IDRW203(debug=True)
  d.Connect()
  ### Create message ###
  m = Msg(cmd, arg)
  m.Display()
  print(m.GetChecksum())
  print(m.IsChksumGood(m.GetChecksum()))
  ### Let's send it ###
  d.SendMsg(m)
  d.RecvRsp().Display()
  ### Close ###
  d.Disconnect()

##############################################################
#
# read_id: Function just keeps reading until it sees a token.
#
##############################################################
def read_id(d=None):
  if d == None:
    print('No device specified in parameters!')
  cmd_test_noconnect(b'\x14',b'\x03',d) # RF Start
  while True:
    r = cmd_test_noconnect(CMD_EM4100_READ, b'',d)
    #r = cmd_test_noconnect(b'\x14', b'\x01',d)
    if r.RspLen() > 6:
      break
  cmd_test_noconnect(b'\x14',b'\x02',d) # RF Stop
  
if __name__ == '__main__':
  ### Connect ###
  d = CTX_IDRW203(debug=False)
  d.Connect() 
  read_id(d)
  cmd_test_noconnect(CMD_BELL,b'\x09',d)
  #cmd_test_noconnect(b'\x12',b'\x00'*5,d)  # T5577 Reset
  #cmd_test_noconnect(b'\x14',b'\x03',d)    # RF Start
  #cmd_test_noconnect(b'\x14',b'\x02',d)    # RF Stop
  d.Disconnect()

  ####### Some simple test code #######
  #####################################

  ### Create Bell message ###
  #m = Msg(CMD_BELL, b'\x01')
  #m.Display()
  #print(m.GetChecksum())
  #print(m.IsChksumGood(m.GetChecksum()))
  ### Test creating message from message ###
  #q = Msg.fromMsg(m.GetMsg())
  #q.Display()
  ### Let's send Bell message 3X ###
  #d.SendMsg(m)
  #d.RecvRsp().Display()
  #d.SendMsg(m)
  #d.RecvRsp().Display()
  #d.SendMsg(m)
  #d.RecvRsp().Display()
  #m = Msg(CMD_GET_SUPPORT, b'')
  #m.Display()
  #d.SendMsg(m)
  #d.RecvRsp(exp=b'\x80').Display()
  #m = Msg(CMD_EM4100_READ, b'')
  #m.Display()
  #d.SendMsg(m)
  #d.RecvRsp(raw_display=True).Display()
  ### Disconnect ###
  #d.Disconnect()

