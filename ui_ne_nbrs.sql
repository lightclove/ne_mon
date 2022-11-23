-- Created 02-12s-2021
-- Представление предназачено для отображения значений соседей сетевых элементаов, полученных с помощью LLDP
-- а также для отображения топологии в клиенте 
CREATE VIEW osi.ui_nbrs AS
----------------------------------------------------------------------------------------------------------------------
SELECT
       osi.snmp_message.ip,
       osi.snmp_message.ne_id,
       right(ltree2text(snmp_value_active.oid), 2) as port,
       osi.snmp_value_active.status,
       osi.snmp_value_active.value,
      --c0a816c5000000c8
       osi.hex_to_numeric(substring(left(osi.snmp_value_active.value,8) from 1 for 2)) || '.' ||
       osi.hex_to_numeric(substring(left(osi.snmp_value_active.value,8) from 3 for 2)) || '.' ||
       osi.hex_to_numeric(substring(left(osi.snmp_value_active.value,8) from 5 for 2)) || '.' ||
       osi.hex_to_numeric(substring(left(osi.snmp_value_active.value,8) from 7 for 2))
       AS neighbour_ip,
       CASE WHEN char_length(snmp_value_active.value)  <= 16
            THEN
               left(osi.snmp_value_active.value,8)
       ELSE
               substring(left(osi.snmp_value_active.value,12) from 5 for 17 )
       END
       AS neighbours,
       right(osi.snmp_value_active.value,2) as equipment_type
----------------------------------------------------------------------------------------------------------------------
FROM
       osi.snmp_message,
       osi.snmp_value_active
       --net.ne
----------------------------------------------------------------------------------------------------------------------
WHERE
        --net.ne.id = osi.ui_nbrs.ne_id
        osi.snmp_message.id = osi.snmp_value_active.message_id
AND     osi.snmp_value_active.value <> ''
AND     osi.snmp_value_active.value not like '182%'
AND     osi.snmp_value_active.oid ~ '1.3.6.1.4.1.119.2.3.69.5.4.1.1.*';
----------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------
--drop view osi.ui_nbrs_arr;
CREATE VIEW osi.ui_nbrs_arr
----------------------------------------------------------------------------------------------------------------------
AS SELECT
     osi.ui_nbrs.ip as ne_ipaddr,
     array_agg(osi.ui_nbrs.neighbour_ip) as ne_nbrs
     ,net.ne.name,
     net.ne.id
----------------------------------------------------------------------------------------------------------------------
FROM osi.ui_nbrs, net.ne
----------------------------------------------------------------------------------------------------------------------
WHERE osi.ui_nbrs.ip = net.ne.ip
----------------------------------------------------------------------------------------------------------------------
GROUP BY osi.ui_nbrs.ip,net.ne.name, net.ne.id ;
----------------------------------------------------------------------------------------------------------------------
----------------------------------------------------------------------------------------------------------------------
-- Created 29-11-2021
--
-- CREATE VIEW  osi.ui_ne_nbrs AS
-- ----------------------------------------------------------------------------------------------------------------------
--     SELECT
--         osi.snmp_message.ip,
--         osi.snmp_message.ne_id,
--         osi.snmp_value_active.oid,
--         right(cast(snmp_value_active.oid as text) , 2) as port, --@ToDo *Find out how to fetch the last chidren from the ltree*
--         right(ltree2text(snmp_value_active.oid), 2) as port,
--         osi.snmp_value_active.status,
--         left(osi.snmp_value_active.value,8) as lldp_neighbour_value,
--         hex_to_numeric(substring(left(osi.snmp_value_active.value,8) from 1 for 2)) ||'.' ||
--         hex_to_numeric(substring(left(osi.snmp_value_active.value,8) from 3 for 2)) || '.' ||
--         hex_to_numeric(substring(left(osi.snmp_value_active.value,8) from 5 for 2)) || '.' ||
--         hex_to_numeric(substring(left(osi.snmp_value_active.value,8) from 7 for 2)) as neighbour_ip_encoded,
--         right(osi.snmp_value_active.value,8) as equipment_type,
--         right(osi.snmp_value_active.value,2) as equipment_type_encoded
--         ,net.tmp_new.*
-- ----------------------------------------------------------------------------------------------------------------------
--     FROM
--         osi.snmp_message,
--         osi.snmp_value_active
--         ,net.tmp_new
-- ----------------------------------------------------------------------------------------------------------------------
--     WHERE
--         osi.snmp_message.id = osi.snmp_value_active.message_id
--     AND
--         osi.snmp_value_active.oid ~ '1.3.6.1.4.1.119.2.3.69.5.4.*'
-- ------------------------------------------------------------------------------------------------------------------------
-- 
--     AND
--       osi.snmp_value_active.value <> '' AND osi.snmp_value_active.value not like '182%'
--     AND
--        osi.snmp_value_active.value <> '' AND length(osi.snmp_value_active.value)<=16
-- ;
-- ------------------------------------------------------------------------------------------------------------------------
-- ALTER TABLE ui_ne_nbrs
--     OWNER TO backend;
-- ------------------------------------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------------------------------------
-- alter table ui_neighbours
--     owner to backend;
-- ------------------------------------------------------------------------------------------------------------------------
-- ------------------------------------------------------------------------------------------------------------------------
-- select * from ui_ne_nbrs;
------------------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------------------
--AND     osi.snmp_message.ne_id = net.tmp_new.id
--select min(dt) from osi.snmp_message
--select log::json->'0'->>'fl' from .osi.snmp_message
--select log::json->'0' from .osi.snmp_message text
--select snmp_value_active.oid, task.proc from osi.snmp_value_active, net.task.id where osi.snmp_value_active.message_id = net.task.id


-- SELECT  net.task.id,
--         net.task.schedule,
--         net.task.proc,
--         net.flow.task_id,
--         osi.snmp_value_active.oid,
--         osi.snmp_value_active.value
-- FROM    net.task,
--         net.flow,
--         osi.snmp_value_active
-- WHERE   net.task.id = net.flow.task_id


--flow.id -> snmp_message.log."fl"

--SELECT osi.snmp_message.log::json->'0'->>'fl' from osi.snmp_message
--SELECT cast(osi.snmp_message.log::json->'0'->>'fl' as INTEGER) from osi.snmp_message
/*
Анализ LLDP:
0  1    2   3   4   5    6  7    8    9   10  11  12  13  14   15  16  17  18  20
01 12   c0  a8  14  42   00 00   00   c8  d4  92  34  b4  b3   c0  00  00  00  29
        192 168 20  66                200 212 146 52  180 179  192 0   0   0   41
0  1  2  3  4  5  6  7
c0 a8 16 c5 00 00 00 c8

 */
