import requests
import logging
import dramatiq
from periodiq import PeriodiqMiddleware, cron

aBroker = dramatiq.get_broker()
aBroker.add_middleware(PeriodiqMiddleware(skip_delay=30))


@dramatiq.actor(periodic=cron('* * * * *'))
def once():
    pass


@dramatiq.actor(periodic=cron('* * * * *'))
def one_min():
    pass


@dramatiq.actor(periodic=cron('1,6,11,16,21,26,31,36,41,46,51,56 * * * *'))
def five_min():
    pass


@dramatiq.actor(periodic=cron('5,20,35,50 * * * *'))
def fifteen_min():
    pass


@dramatiq.actor(periodic=cron('0 * * * *'))
def one_hour():
    pass


@dramatiq.actor(periodic=cron('0 0 * * *'))
def one_day_midnight():
    pass
