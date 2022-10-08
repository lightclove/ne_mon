# cTrap_Sender.py - Custom Trap Sender
# python2 cTrap_Sender.py "Musson" "192.168.88.236" 169 "1.3.6.1.2.1.1.1.0" "Test Custom Trap send" "1.3.6.1.2.1.1.3.0"

import sys
from pysnmp.hlapi import *
from pysnmp import debug
debug.setLogger(debug.Debug('msgproc'))
try:
     next(sendNotification(SnmpEngine(),
          #CommunityData('Musson'),
          CommunityData(str(sys.argv[1])),
          #UdpTransportTarget(('192.168.88.236', 169)),
          UdpTransportTarget((str(sys.argv[2]), str(sys.argv[3]))),
          ContextData(),
          'trap',
          # sequence of custom OID-value pairs
          [ObjectType(ObjectIdentity(sys.argv[4]), OctetString(sys.argv[5])),
           ObjectType(ObjectIdentity(sys.argv[6]), Integer32(42))]))

except:
     print('Usage example:')
     print('python2 cTrap_Sender.py "Musson" "192.168.88.236" 169 "1.3.6.1.2.1.1.1.0" "Test Custom Trap send" "1.3.6.1.2.1.1.3.0"')

# python2 cTrap_Sender.py "Musson" "192.168.88.236" 169 "1.3.6.1.2.1.1.1.0" "14: 29:14.159[S1AP] - Disconnected" "1.3.6.1.2.1.1.3.0"
# python2 cTrap_Sender.py "Musson" "192.168.88.236" 169 "1.3.6.1.2.1.1.1.0" "14: 29:14.159[S1AP] - Connect error (code=111)" "1.3.6.1.2.1.1.3.0"






























# from pysnmp.hlapi import *
# from pysnmp import debug
# #snmptrapd -v2c -c Musson 192.168.88.236 169 .1.3.6.1.2.1.1.1.0 'Test Custom Trap send' .1.3.6.1.2.1.1.3.0
# def sendCustomTrap(community, ipA, port, oid_f,  message, oid_s  ):
#     print()
#     debug.setLogger(debug.Debug('msgproc'))
#     next(sendNotification(SnmpEngine(),
#                       CommunityData(community), #='Musson'
#                       UdpTransportTarget(ipA, port), #='192.168.88.236' , = 162
#                       ContextData(),
#                       'trap',
#                       # sequence of custom OID-value pairs
#                       [ObjectType(ObjectIdentity(oid_f), #='1.3.6.1.2.1.1.1.0'
#                                   OctetString(message)), #='Test Custom Trap send'
#                        ObjectType(ObjectIdentity(oid_s), #='1.3.6.1.2.1.1.3.0'
#                                   Integer32(42))]))
#
# sendCustomTrap('Musson', '192.168.88.236', 169, '1.3.6.1.2.1.1.1.0','Test Custom Trap send','1.3.6.1.2.1.1.3.0')

