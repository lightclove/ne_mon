import asyncio, logging, sys, traceback
from binascii import hexlify
from datetime import datetime
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from sqlalchemy import Table, Column, MetaData, create_engine, PickleType, Integer, String, JSON, Boolean
from sqlalchemy.pool import NullPool
import mond, logmon

print = logmon.logger.info

cred = {}


class credential(mond.Base):
    __tablename__ = 'credential'
    id = Column(Integer, primary_key=True)
    param = Column(JSON)
    name = Column(String)
    enabled = Column(Boolean)


def TrapCredential():
    try:
        print('monl credentials start')
        engine = create_engine(mond.enter, poolclass=NullPool,
                               connect_args={'options': '-csearch_path={}'.format('net'), 'connect_timeout': 5})
        session = Session(engine)
        cred_set = session.query(credential).filter(credential.enabled == True).filter(
            credential.param['type'] == '"trap"').all()
        cred['ip'] = cred_set[0].param['ip']
        cred['port'] = cred_set[0].param['port']
        cred['version'] = cred_set[0].param['version']
        cred['community'] = cred_set[0].param['community']
        print('monl credentials SUCCESS')
    except Exception as e:
        logging.error(sys.exc_info())
        traceback.print_exc(file=sys.stdout)
        file = open(logmon.logfilename, 'a')
        traceback.print_exc(file=file)
        file.close()
    finally:
        session.close()
        engine.dispose()


def TrapInitialize(ip='READ_IP', port=162, version=2, community='public', *arg, **kwarg):
    # Get the event loop for this thread
    loop = asyncio.get_event_loop()
    # Create SNMP engine with autogenernated engineID and pre-bound
    # to socket transport dispatcher
    snmpEngine = engine.SnmpEngine()
    # put this in your script's initialization section
    context = {}

    def request_observer(snmpEngine, execpoint, variables, context):
        pdu = variables['pdu']
        traptype = ''
        request_id = 0
        context['error-status'] = ''
        context['error-index'] = ''
        if pdu.__class__.__name__ == 'SNMPv2TrapPDU':
            traptype = 2
            request_id = pdu['request-id']
            context['error-status'] = pdu['error-status']
            context['error-index'] = pdu['error-index']
        elif pdu.__class__.__name__ == 'InformRequestPDU':
            traptype = 3
            request_id = pdu['request-id']
            context['error-status'] = pdu['error-status']
            context['error-index'] = pdu['error-index']
        elif pdu.__class__.__name__ == 'TrapPDU':
            traptype = 1
        else:
            traptype = -1
        # this is just a way to pass fetched data from the callback out
        context['request-id'] = int(request_id)
        context['traptype'] = traptype

    snmpEngine.observer.registerObserver(request_observer, 'rfc3412.receiveMessage:request', cbCtx=context)
    # Transport setup
    # UDP over IPv4, first listening interface/port
    trp1 = udp.UdpTransport().openServerMode((ip, port))
    config.addTransport(snmpEngine, udp.domainName + (1,), trp1)
    print('Start TrapListener on {} port {}'.format(ip, port))
    # UDP over IPv4, second listening interface/port
    # trp2 = udp.UdpTransport().openServerMode(('0.0.0.0', 162))
    # config.addTransport(snmpEngine,udp.domainName + (2,),trp2)
    # print('Start TrapListener on {} port {}'.format('0.0.0.0', 162))
    # SNMPv1/2c setup
    # SecurityName <-> CommunityName mapping
    config.addV1System(snmpEngine, 'area', community)
    # Callback function for receiving notifications
    # noinspection PyUnusedLocal
    def cbFun(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
        transportDomain, transportAddress = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
        print('Notification from %s, SNMP Engine %s, '
              'Context %s' % (transportAddress, contextEngineId.prettyPrint(), contextName.prettyPrint()))
        print(context)
        print(transportDomain)
        for oid, val in varBinds:
            print('%s = %s (%s)' % (oid.prettyPrint(), val.prettyPrint(), val.__class__.__name__))
        dt = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-4] + '+0'
        cnt = 0
        resvar = 'INSERT INTO o.snmp_value_buffer (message_id,oid,type,value) VALUES'
        resvar += '\n'
        for oid, val in varBinds:
            cnt += 1
            if cnt > 1:
                resvar += ', \n'
            snmp_type = val.__class__.__name__
            aoid = oid.prettyPrint().strip().strip('.')
            if val.prettyPrint() != '' and (snmp_type == 'Integer' or snmp_type == 'Counter32'):
                avalue = int(val.prettyPrint())
            else:
                s = str("")
                s += val.prettyPrint()
                avalue = "'" + s + "'"
            resvar += "('##TRAP##','{}','{}',{})".format(aoid, snmp_type, avalue)
        resvar += ';'
        print(resvar)

        res = {}
        res['from_ip'] = transportAddress[0]
        res['traptype'] = context['traptype']
        if context['traptype'] == 2 or context['traptype'] == 3:
            res[
                'log'] = '{{\"0\":{{\"dt\":\"{}\",\"op\":\"LSTN1\",\"fl\":\"##FLOW##\",\"port_from\":\"{}\",\"request-id\":\"{}\",\"error-status\":\"{}\",\"error-index\":\"{}\" }}}}'. \
                format(dt, transportAddress[1], context['request-id'], context['error-status'], context['error-index'])
        elif context['traptype'] == 1:
            res['log'] = '{{\"0\":{{\"dt\":\"{}\",\"op\":\"LSTN1\",\"fl\":\"##FLOW##\",\"port_from\":\"{}\" }}}}'. \
                format(dt, transportAddress[1])
        print(res)

        mond.trap_task_res.send(res, resvar)
        # mond.trap_task(res, resvar)

    # Register SNMP Application at the SNMP engine
    ntfrcv.NotificationReceiver(snmpEngine, cbFun)

    # Run asyncio main loop
    loop.run_forever()


TrapCredential()
TrapInitialize(cred['ip'], cred['port'], cred['version'], cred['community'])
