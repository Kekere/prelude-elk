Select Distinct prelude_correlationalert._message_ident, prelude_correlationalert.name, prelude_classification.text, address.address, prelude_service.iana_protocol_name, prelude_service.name, prelude_service.port, time as createtime
from prelude_classification left join prelude_correlationalert 
 on prelude_correlationalert._message_ident=prelude_classification._message_ident
inner join (Select * from prelude_address where prelude_address._parent_type='S') as address on prelude_classification._message_ident=address._message_ident
inner join prelude_service on address._message_ident=prelude_service._message_ident
inner join (Select * from prelude_createtime where prelude_createtime._parent_type='A') as createtime on prelude_service._message_ident=createtime._message_ident
where time > :sql_last_value and time < NOW() ORDER BY time ASC;
