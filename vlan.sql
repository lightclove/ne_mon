SELECT q0.name AS ne_name,
       q0.ip,
       q0.port,
       q0.slot,
       q0.vlan_id,
       q1.type,
       q2.status,
       q0._ne_id,
       q0.endltree as _ltr
FROM (
      SELECT m.ne_id AS _ne_id,
             n.name,
             n.ip,
             mib.nec_ifindex_slot(ltree2text(subltree(v.oid, nlevel(v.oid) - 2, nlevel(v.oid)-1))::int) AS slot,
             mib.nec_ifindex_port(ltree2text(subltree(v.oid, nlevel(v.oid) - 2, nlevel(v.oid)-1))::int) AS port,
             ltree2text(subltree(v.oid, nlevel(v.oid) - 1, nlevel(v.oid)))::int AS vlan_id,
             ltree2text(subltree(v.oid, nlevel(v.oid) - 2, nlevel(v.oid))) AS endltree
      FROM osi.snmp_message m,
           osi.snmp_value v,
           net.ne n
      WHERE v.message_id = m.id
        AND m.ne_id = n.id
        AND v.status = 1
        AND m.type = 0
        AND v.oid <@ '1.3.6.1.4.1.119.2.3.69.501.5.20.2.1.4'::ltree
      ORDER BY m.ne_id
     ) q0
         LEFT JOIN (SELECT m.ne_id,
                           (o.syntax ->> v.value::text)::text AS type,
                           ltree2text(subltree(v.oid, nlevel(v.oid) - 2, nlevel(v.oid))) AS endltree
                    FROM osi.snmp_message m,
                         osi.snmp_value v,
                         mib.object o
                    WHERE v.message_id = m.id
                      AND v.status = 1
                      AND v.oid <@ '1.3.6.1.4.1.119.2.3.69.501.5.20.2.1.4'::ltree
                      AND o.oid <@ '1.3.6.1.4.1.119.2.3.69.501.5.20.2.1.4'::ltree
                    ORDER BY m.ne_id) q1 ON q0._ne_id = q1.ne_id AND q0.endltree = q1.endltree
         LEFT JOIN (SELECT m.ne_id,
                           (o.syntax ->> v.value::text)::text AS status,
                           ltree2text(subltree(v.oid, nlevel(v.oid) - 2, nlevel(v.oid))) AS endltree
                    FROM osi.snmp_message m,
                         osi.snmp_value v,
                         mib.object o
                    WHERE v.message_id = m.id
                      AND v.status = 1
                      AND v.oid <@ '1.3.6.1.4.1.119.2.3.69.501.5.20.2.1.5'::ltree
                      AND o.oid <@ '1.3.6.1.4.1.119.2.3.69.501.5.20.2.1.5'::ltree
                    ORDER BY m.ne_id) q2 ON q0._ne_id = q2.ne_id AND q0.endltree = q2.endltree
ORDER BY 1,2,3,4,5;





