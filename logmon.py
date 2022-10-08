import logging, time

logfilename = '/opt/log/ne_mon.log'
logging.basicConfig(level=logging.ERROR,
                    format='%(asctime)s.%(msecs)d,%(levelname)s,%(filename)s,func:%(funcName)s,USR:%(name)s,PID:%(process)d,%(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logging.Formatter.converter = time.gmtime
fmt = logging.Formatter(
    fmt='%(asctime)s.%(msecs)d,%(levelname)s,%(filename)s,func:%(funcName)s,USR:%(name)s,PID:%(process)d,%(message)s',
    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()
# logger.setLevel(logging.ERROR)
handler = logging.FileHandler(logfilename, 'a')
logger.addHandler(handler)
handler.setFormatter(fmt)
print = logger.info
