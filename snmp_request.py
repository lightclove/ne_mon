import traceback, time, sys, logging
from time import timezone
from binascii import hexlify
from datetime import datetime
import easysnmp
from easysnmp import Session
import logmon


def SnmpRequest(ip='your_ip_here',
                port=161,
                ne_id=0,
                version=2,
                community='public',
                oid=["1.3.6.1.2.1.25.1"],
                callto='walk',
                flow=0, non_repeaters=0,
                max_repetitions=10,
                *arg, **kwarg):
    try:
        logging.info(
            'SnmpRequest > ip:{},ne_id:{},version:{},community:{},oid:{},callto:{},flow:{},non_repeaters:{},max_repetitions:{}'.
                format(ip, ne_id, version, community, oid, callto, flow, non_repeaters, max_repetitions))
        res = ''
        rescode = 0
        reslog = ''
        session = Session(hostname=ip,
                          remote_port=port,
                          community=community,
                          version=version,
                          use_long_names=True,
                          use_numeric=True)
        dtsent_b = datetime.utcnow()

        if callto == 'bulkwalk':
            items = session.bulkwalk(oid, non_repeaters, max_repetitions)  
        elif callto == 'get':
            items = session.get(oid)
        elif callto == 'getbulk':
            items = session.get_bulk(oid, non_repeaters, max_repetitions) 
        elif callto == 'getnext':
            items = session.get_next(oid)
        elif callto == 'walk':
            items = session.walk(oid)
        else:
            rescode = 102
        if rescode != 102 and items.__len__() != 0:
            dt_b = datetime.utcnow()
            dt = dt_b.strftime('%Y-%m-%d %H:%M:%S.%f')[:-2]
            rtd = str((dt_b - dtsent_b).seconds) + '.' + str((dt_b - dtsent_b).microseconds)[:-3]
            cnt = 0
            res = 'INSERT INTO osi.snmp_value_buf2 (message_id,oid,type,value) VALUES'
            res += '\n'
            for item in items:
                cnt += 1
                if cnt > 1:
                    res += ', \n'

                aoid = (item.oid.strip() + '.' + item.oid_index.strip()).lstrip('.')
                if item.snmp_type == 'OCTETSTR' and item.value != '':
                    avalue = "'" + str(hexlify(item.value.encode('latin-1'))).lstrip('b').strip("'") + "'"
                elif item.snmp_type == 'INTEGER' or item.snmp_type == 'GAUGE':
                    avalue = int(item.value)
                else:
                    s = str("")
                    s += item.value
                    avalue = "'" + s + "'"
                res += "(##MSSG##, '{}','{}',{})".format(aoid, item.snmp_type, avalue)
            res += ';'
            reslog = '{{\"0\":{{\"dt\":\"{}\",\"rtd\":\"{}\", \"op\":\"EASY1\",\"fl\":\"{}\"}}}}'.format(dt, rtd, flow,
                                                                                                         ne_id)
        elif items.__len__() == 0:
            rescode = 103
    except Exception as e:
        if e.__class__ == SystemError:
            if e.__str__() == 'TypeError: an integer is required (got type NoneType)':
                rescode = 106
            else:
                rescode = 104
        elif e.__class__ == easysnmp.exceptions.EasySNMPTimeoutError:
            rescode = 104
        elif e.__class__ == easysnmp.exceptions.EasySNMPNoSuchNameError:
            rescode = 105
        else:
            rescode = 100
        logging.error(sys.exc_info())
        traceback.print_exc(file=sys.stdout)
        file = open(logmon.logfilename, 'a')
        traceback.print_exc(file=file)
        file.close()
    finally:
        logging.info('SnmpRequest > rescode:{},res count lines:{}, reslog:{}'.format(rescode, res.count('\n'), reslog))
    return res, reslog, rescode


def SnmpRequestRescode(code):
    value = {0: 'success',
             100: 'unknown exception',
             102: '<callto> parameter is not callable',
             103: 'empty response received',
             104: 'timeout',
             105: 'no such name encountered',
             106: 'param value is not correct'}
    return value.get(code, 'rescode not exists')
