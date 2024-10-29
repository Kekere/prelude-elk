Select Distinct prelude_correlationalert._message_ident, prelude_correlationalert.name, prelude_classification.text, address.address, service.iana_protocol_name, service.name, service.port, time as createtime, prelude_impact.description, prelude_impact.severity, prelude_impact.completion
from prelude_classification left join prelude_correlationalert 
 on prelude_correlationalert._message_ident=prelude_classification._message_ident
inner join (Select * from prelude_address where prelude_address._parent_type='S') as address on prelude_classification._message_ident=address._message_ident
inner join (Select * from prelude_service where prelude_service._parent_type='S') as service on address._message_ident=service._message_ident
inner join (Select * from prelude_createtime where prelude_createtime._parent_type='A') as createtime on service._message_ident=createtime._message_ident
inner join prelude_impact on createtime._message_ident=prelude_impact._message_ident
where time > :sql_last_value and time < NOW() ORDER BY time ASC;
