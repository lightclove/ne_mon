create view net.net_elements_list
            (region, site_num, site_addr, ne_name, ne_segment, primary_ip, opposite_ip, subnet_mask, default_gw,
             mac_address, model, sw_version, snmp_state_e, trap_state, ftp_state_e, _ne_id)
as
SELECT s.region,
       s.name                                                               AS site_num, 
       s.address                                                            AS site_addr,
       n.name                                                               AS ne_name,
       CASE m1.oid_value
           WHEN '192.168.0.10'::text THEN '2-La'::text
           WHEN '192.168.0.13'::text THEN '1-Ur00'::text
           WHEN '192.168.0.43'::text THEN '1-Shi'::text
           WHEN '192.168.0.41'::text THEN '2-Psn'::text
           WHEN '192.168.0.49'::text THEN '1-Merh'::text
           WHEN '192.168.0.81'::text THEN '1-XSM'::text
           WHEN '192.168.0.121'::text THEN '2-OK'::text
           WHEN '192.168.0.217'::text THEN '1-KSM'::text
           WHEN '192.168.0.225'::text THEN '1-KKL'::text
           WHEN '192.168.1.33'::text THEN '1-Nm'::text
           WHEN '192.168.1.97'::text THEN '1-GBt'::text
           WHEN '192.168.1.177'::text THEN '1-Yard'::text
           WHEN '192.168.1.193'::text THEN '1-SgBlr'::text
           WHEN '192.168.2.193'::text THEN '1-Srg'::text
           WHEN '192.168.1.73'::text THEN '1-UrP'::text
           ELSE NULL::text
           END                                                              AS ne_segment,
       n.ip                                                                 AS primary_ip,
       m2.oid_value                                                         AS opposite_ip,
       m3.oid_value                                                         AS subnet_mask,
       m1.oid_value                                                         AS default_gw,
       m4.oid_value                                                         AS mac_address,
       (i.modelname::text || ' '::text) || i.modelnumber::text              AS model,
       rtrim(m4.oid_value::text, '.0'::text)::character varying             AS sw_version,
       to_char(timezone('-5'::text, q1.min), 'YYYY-MM-DD HH24:MI:SS'::text) AS snmp_state_e,
       v_trap_state.resval                                                  AS trap_state,
       COALESCE(to_char(timezone('-5'::text, q2.max), 'YYYY-MM-DD HH24:MI:SS'::text),
                '<disconn>'::character varying::text)                       AS ftp_state_e,
       n.id                                                                 AS _ne_id
FROM net.site s,
     net.identity i,
     osi.v_trap_state,
     net.ne n
         LEFT JOIN (SELECT m.ne_id,
                           min(m.dt) AS min
                    FROM osi.snmp_message m,
                         osi.snmp_value v
                    WHERE v.message_id = m.id
                      AND v.status = 1
                      AND v.oid <@ '1.3.6.1.4.1.119.2.3.69.501.7'::ltree
                    GROUP BY m.ne_id
                    ORDER BY m.ne_id) q1 ON n.id = q1.ne_id
         LEFT JOIN (SELECT r.ne_id,
                           max(r.dt) AS max
                    FROM osi.ftp_rmon r
                    GROUP BY r.ne_id
                    ORDER BY r.ne_id) q2 ON n.id = q2.ne_id
         LEFT JOIN (SELECT t.ne_id,
                           t.endltree,
                           t.oid_value
                    FROM osi.tmp_snmp_value t
                    WHERE t.oid_name::text = 'ipeSysDefaultGateway'::text
                    ORDER BY t.ne_id) m1 ON n.id = m1.ne_id
         LEFT JOIN (SELECT t.ne_id,
                           t.endltree,
                           t.oid_value
                    FROM osi.tmp_snmp_value t
                    WHERE t.oid_name::text = 'sysOppositeIpAddress'::text
                    ORDER BY t.ne_id) m2 ON n.id = m2.ne_id
         LEFT JOIN (SELECT t.ne_id,
                           t.endltree,
                           t.oid_value
                    FROM osi.tmp_snmp_value t
                    WHERE t.oid_name::text = 'ipeSysSubnetMask'::text
                    ORDER BY t.ne_id) m3 ON n.id = m3.ne_id
         LEFT JOIN (SELECT t.ne_id,
                           t.endltree,
                           t.oid_value
                    FROM osi.tmp_snmp_value t
                    WHERE t.oid_name::text = 'ipeSysMacAddress'::text
                    ORDER BY t.ne_id) m4 ON n.id = m4.ne_id
         LEFT JOIN (SELECT t.ne_id,
                           t.endltree,
                           t.oid_value
                    FROM osi.tmp_snmp_value t
                    WHERE t.oid_name::text = 'ipeSysInvSoftwareVersion'::text
                    ORDER BY t.ne_id) m5 ON n.id = m5.ne_id
        
                    
WHERE n.site_id = s.id
  AND n.identity_id = i.id
  AND n.identity_id <> 0
  AND v_trap_state.ne_id = n.id
ORDER BY n.ip;

alter table net.net_elements_list
    owner to backend;

