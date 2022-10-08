import traceback, time, logging, sys
from time import sleep
import json
import dramatiq
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, types, Table, Column
from sqlalchemy.util import NoneType
from sqlalchemy import Table, Column, MetaData, create_engine, PickleType, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from sqlalchemy import Table, Column, MetaData, create_engine, PickleType, Integer, String, JSON, Boolean, DateTime
from sqlalchemy.pool import NullPool
from snmp_request import SnmpRequest, SnmpRequestRescode
from ftp_request import FtpSync, FtpUpload, FtpSyncRescode
from datetime import datetime
import logmon

print = logmon.logger.info
enter = ''
engine = create_engine(enter, poolclass=NullPool,
                       connect_args={'options': '-csearch_path={}'.format('public'), 'connect_timeout': 5})
Base = declarative_base()


class virtual_task(Base):
    __tablename__ = 'v_task'
    __table_args__ = {'schema': 'net'}
    id = Column(Integer, primary_key=True)
    task_id = Column(Integer)
    proc = Column(JSON)
    schedule = Column(String)
    enabled = Column(Boolean)
    ip = Column(String)
    param = Column(JSON)
    ne_id = Column(Integer)


class task(Base):
    __tablename__ = 'task'
    __table_args__ = {'schema': 'net'}
    id = Column(Integer, primary_key=True)
    proc = Column(JSON)
    schedule = Column(String)
    enabled = Column(Boolean)
    ne_id = Column(Integer)


class flow(Base):
    __tablename__ = 'flow'
    __table_args__ = {'schema': 'net'}
    id = Column(Integer, primary_key=True)
    descr = Column(String)
    log = Column(JSON)
    task_id = Column(Integer)


class alarm(Base):
    __tablename__ = 'alarm'
    __table_args__ = {'schema': 'net'}
    id = Column(Integer, primary_key=True)
    category = Column(String)
    description = Column(String)
    severity = Column(String)
    ne_id = Column(Integer)
    log = Column(JSON)


class snmp_message(Base):
    __tablename__ = 'snmp_message'
    __table_args__ = {'schema': 'osi'}
    id = Column(Integer, primary_key=True)
    type = Column(Integer)
    ip = Column(String)
    ne_id = Column(Integer)
    log = Column(JSON)
    dt = Column(DateTime)


@dramatiq.actor()
def once():
    run_task('once')


@dramatiq.actor()
def one_min():
    run_task('one_min')


@dramatiq.actor()
def five_min():
    run_task('five_min')


@dramatiq.actor()
def fifteen_min():
    run_task('fifteen_min')


@dramatiq.actor()
def one_hour():
    run_task('one_hour')


@dramatiq.actor()
def six_hours():
    run_task('six_hours')


@dramatiq.actor()
def one_day_midnight():
    run_task('one_day_midnight')


def run_task(period='once'):
    try:
        print('actor_name:' + period)
        session = Session(engine)

        total = session.query(virtual_task). \
            filter(virtual_task.enabled == True). \
            filter(virtual_task.schedule == period). \
            filter(virtual_task.proc['type'] == '"snmp"'). \
            filter(virtual_task.param['type'] == '"snmp"').all()
        for el in total:
            logging.info(
                'actor_name: {}, proc:{},schedule:{},enabled:{},ip:{},param:{},ne_id:{}'.format(period, el.proc,
                                                                                                el.schedule, el.enabled,
                                                                                                el.ip, el.param,
                                                                                                el.ne_id))
            oidset = []
            if el.proc['request'] == 'bulkwalk' or el.proc['request'] == 'walk':
                for oid in el.proc['oid']:
                    oidset.append(oid)
            else:
                oidset.append(el.proc['oid'])
            for oid in oidset:
                new_log = '{{"ip":"{}","ne_id":{},"oid":"{}"}}'.format(el.ip, el.ne_id, oid)
                json_log = json.loads(new_log)
                new_flow = flow(descr='snmp get {} from {} for {}'.format(period, el.ip, oid), log=json_log,
                                task_id=el.task_id)
                session.add(new_flow)
                session.commit()
                snmp_task2.send(ip=el.ip,
                                port=el.param['port'],
                                ne_id=el.ne_id,
                                version=el.param['version'],
                                community=el.param['community'],
                                oid=oid,
                                callto=el.proc['request'],
                                flow=new_flow.id,
                                non_repeaters=el.proc.get('non_repeaters', 0),
                                max_repetitions=el.proc.get('max_repetitions', 10))
        if period == 'once':
            for el in total:
                session.query(task).filter(task.id == el.task_id).update({"enabled": False})
        session.commit()

        total = session.query(virtual_task). \
            filter(virtual_task.enabled == True). \
            filter(virtual_task.schedule == period). \
            filter(virtual_task.proc['type'] == '"ftp"'). \
            filter(virtual_task.param['type'] == '"ftp"').all()
        for el in total:
            logging.info(
                'actor_name: {}, proc:{},schedule:{},enabled:{},ip:{},param:{},ne_id:{}'.format(period, el.proc,
                                                                                                el.schedule, el.enabled,
                                                                                                el.ip, el.param,
                                                                                                el.ne_id))
            new_log = '{{"ip":"{}","ne_id":{}}}'.format(el.ip, el.ne_id)
            json_log = json.loads(new_log)
            new_flow = flow(descr='ftp get {} from {}'.format(period, el.ip), log=json_log, task_id=el.task_id)
            session.add(new_flow)
            session.commit()
            ftp_task.send(ip=el.ip,
                          ne_id=el.ne_id,
                          lgn=el.param['lgn'],
                          pwd=el.param['pwd'],
                          flow=new_flow.id)
        if period == 'once':
            for el in total:
                session.query(task).filter(task.id == el.task_id).update({"enabled": False})
        session.commit()

        print('actor_name:{} SUCCESS'.format(period))
    except Exception as e:
        logging.error(sys.exc_info())
        traceback.print_exc(file=sys.stdout)
        file = open(logmon.logfilename, 'a')
        traceback.print_exc(file=file)
        file.close()
    finally:
        session.close()


@dramatiq.actor(max_retries=0, max_age=600000)
def snmp_task(flow=0, ip='IP_ADDRESS', port=161, ne_id=0, version=2, community='public', oid='1.3.6.1.2.1.25.1.0',
              callto='getbulk', non_repeaters=0, max_repetitions=10, *arg, **kwarg):
    try:
        print('actor_name:snmp_task')
        res, reslog, rescode = SnmpRequest(ip, port, ne_id, version, community, oid, callto, flow, non_repeaters,
                                           max_repetitions, *arg, **kwarg)
        session = Session(engine)
        if rescode == 0 and res.strip() != '':
            # ADD RESULTS TO SNMP_MESSAGE----------------------------------------------------------
            json_log = json.loads(reslog)
            new_message = snmp_message(type=0, ip=ip, ne_id=ne_id, log=json_log, dt=datetime.now())
            session.add(new_message)
            session.commit()
            # ADD RESULTS
            session.execute('CALL osi.up_snmp_value_delbuf();')
            new_res = res.replace('##MSSG##', str(new_message.id))
            session.execute(new_res)
            session.execute('CALL osi.up_snmp_value_prepare();')
            session.execute('CALL osi.up_snmp_value_insert();')
            session.commit()
            print('actor_name:snmp_task SUCCESS')
        else:
            # CREATE ALARM
            new_log = '{{"rescode":{},"ip":"{}","oid":"{}","flow":{}}}'.format(rescode, ip, oid, flow)
            json_log = json.loads(new_log)
            new_alarm = alarm(category='nms_ne_snmp',
                              description=SnmpRequestRescode(rescode) + ' ({})'.format(rescode),
                              severity='CRITICAL',
                              ne_id=ne_id,
                              log=json_log)
            session.add(new_alarm)
            session.commit()
            print('actor_name:snmp_task ERROR')
    except Exception as e:
        logging.error(sys.exc_info())
        traceback.print_exc(file=sys.stdout)
        file = open(logmon.logfilename, 'a')
        traceback.print_exc(file=file)
        file.close()
    finally:
        session.close()


@dramatiq.actor(max_retries=0, max_age=600000)
def snmp_task2(flow=0, ip='IP_ADDRESS', port=161, ne_id=0, version=2, community='public',
               oid='1.3.6.1.2.1.25.1.0', callto='getbulk', non_repeaters=0, max_repetitions=10, *arg, **kwarg):
    try:
        print('actor_name:snmp_task2')
        res, reslog, rescode = SnmpRequest(ip, port, ne_id, version, community, oid, callto, flow, non_repeaters,
                                           max_repetitions, *arg, **kwarg)
        
        session = Session(engine)
        if rescode == 0 and res.strip() != '':
            # ADD RESULTS TO SNMP_MESSAGE----------------------------------------------------------
            json_log = json.loads(reslog)
            new_message = snmp_message(type=0, ip=ip, ne_id=ne_id, log=json_log, dt=datetime.now())
            session.add(new_message)
            session.commit()
            # ADD RESULTS
            new_res = res.replace('##MSSG##', str(new_message.id))
            session.execute(new_res)
            session.execute("select * from pgq.insert_event('snmp_insert','on_insert','snmp');")
            session.commit()
            new_message.dt = datetime.now()
            session.commit()
            print('actor_name:snmp_task2 SUCCESS')
        else:
            # CREATE ALARM
            new_log = '{{"rescode":{},"ip":"{}","oid":"{}","flow":{}}}'.format(rescode, ip, oid, flow)
            json_log = json.loads(new_log)
            new_alarm = alarm(category='nms_ne_snmp',
                              description=SnmpRequestRescode(rescode) + ' ({})'.format(rescode),
                              severity='CRITICAL',
                              ne_id=ne_id,
                              log=json_log)
            session.add(new_alarm)
            session.commit()
            print('actor_name:snmp_task2 ERROR')
    except Exception as e:
        logging.error(sys.exc_info())
        traceback.print_exc(file=sys.stdout)
        file = open(logmon.logfilename, 'a')
        traceback.print_exc(file=file)
        file.close()
    finally:
        session.close()


@dramatiq.actor()
def trap_task(res, resvar, *arg, **kwarg):
    try:
        print('actor_name:trap_task')
        session = Session(engine)
        if res != '' and resvar.strip() != '':
            # ADD RESULTS TO FLOW----------------------------------------------------------
            new_flow = flow(descr='trap catch from {}'.format(res['from_ip']))
            session.add(new_flow)
            session.commit()
            # ADD RESULTS TO SNMP_MESSAGE--------------------------------------------------------
            new_log = res['log'].replace('##FLOW##', str(new_flow.id))
            json_log = json.loads(new_log)
            new_message = snmp_message(ip=res['from_ip'], type=res['traptype'], log=json_log, dt=datetime.now())
            session.add(new_message)
            session.commit()
            session.execute('CALL osi.up_snmp_value_delbuf();')
            new_resvar = resvar.replace("'##TRAP##'", str(new_message.id))
            print('##TRAP## message_id = {}, ##FLOW## flow_id = {}'.format(new_message.id, new_flow.id))
            session.execute(new_resvar)
            session.execute('CALL fttbl.up_snmp_value_prepare();')
            session.execute('CALL sdbl.up_snmp_value_insert();')
            session.execute('CALL trdtbl.up_alarmtrap_insert();')
            session.commit()
        print('actor_name:trap_task SUCCESS')
    except Exception as e:
        logging.error(sys.exc_info())
        traceback.print_exc(file=sys.stdout)
        file = open(logmon.logfilename, 'a')
        traceback.print_exc(file=file)
        file.close()
        raise
    finally:
        session.close()


@dramatiq.actor()
def trap_task_res(res, resvar, *arg, **kwarg):
    try:
        print('actor_name:trap_task2')
        # engine = create_engine(enter,connect_args={'options': '-csearch_path={}'.format('public'), 'connect_timeout': 5})
        session = Session(engine)
        if res != '' and resvar.strip() != '':
            # ADD RESULTS TO FLOW----------------------------------------------------------
            new_flow = flow(descr='trap catch from {}'.format(res['from_ip']))
            session.add(new_flow)
            session.commit()
            # ADD RESULTS TO SNMP_MESSAGE--------------------------------------------------------
            new_log = res['log'].replace('##FLOW##', str(new_flow.id))
            json_log = json.loads(new_log)
            new_message = snmp_message(ip=res['from_ip'], type=res['traptype'], log=json_log, dt=datetime.now())
            session.add(new_message)
            session.commit()
            # ADD RESULTS TO SNMP_VALUE----------------------------------------------------------
            new_resvar = resvar.replace("'##TRAP##'", str(new_message.id))
            print('##TRAP## message_id = {}, ##FLOW## flow_id = {}'.format(new_message.id, new_flow.id))
            session.execute(new_resvar)
            session.execute("select * from pgq.insert_event('snmp_insert','on_insert','trap');")
            session.commit()
            new_message.dt = datetime.now()
            session.commit()
            # session.flush([new_message])
    except Exception as e:
        logging.error(sys.exc_info())
        traceback.print_exc(file=sys.stdout)
        file = open(logmon.logfilename, 'a')
        traceback.print_exc(file=file)
        file.close()
        raise
    finally:
        session.close()


@dramatiq.actor(max_retries=0, max_age=600000)
def ftp_task(ip='insert_your_ip_here', lgn='user', pwd='password', flow=0, ne_id=0, *arg, **kwarg):
    try:
        print('actor_name:ftp_task')
        rescode = FtpSync(ip=ip, lgn=lgn, pwd=pwd, flow=flow, ne_id=ne_id, *arg, **kwarg)
        session = Session(engine)
        if rescode == 0:
            # ADD RESULTS
            FtpUpload()
            print('actor_name:ftp_task SUCCESS')
        else:
            # CREATE ALARM
            new_log = '{{"rescode":{},"ip":"{}","flow":{}}}'.format(rescode, ip, flow)
            json_log = json.loads(new_log)
            new_alarm = alarm(category='prod_ftp',
                              description=FtpSyncRescode(rescode) + ' ({})'.format(rescode),
                              severity='CRITICAL',
                              ne_id=ne_id,
                              log=json_log)
            session.add(new_alarm)
            session.commit()
            print('actor_name:ftp_task ERROR')
    except Exception as e:
        logging.error(sys.exc_info())
        traceback.print_exc(file=sys.stdout)
        file = open(logmon.logfilename, 'a')
        traceback.print_exc(file=file)
        file.close()
    finally:
        session.close()
