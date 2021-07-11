Select DISTINCT prelude_classification._message_ident, time as createtime, prelude_classification.ident, prelude_classification.text, prelude_impact.description, prelude_impact.severity, prelude_impact.completion, prelude_impact.type,  prelude_address.address, prelude_source.interface, prelude_userid.type, prelude_userid.name, prelude_user.category 
from prelude_user inner join prelude_createtime on prelude_user._message_ident=prelude_createtime._message_ident 
inner join prelude_userid on prelude_createtime._message_ident=prelude_userid._message_ident 
inner join prelude_classification on prelude_userid._message_ident=prelude_classification._message_ident 
inner join prelude_impact on prelude_classification._message_ident=prelude_impact._message_ident 
inner join prelude_node on prelude_impact._message_ident=prelude_node._message_ident 
inner join prelude_source on prelude_node._message_ident=prelude_source._message_ident 
inner join prelude_address on prelude_source._message_ident=prelude_address._message_ident 
where prelude_address._parent_type='S' and prelude_createtime._parent_type='A' and time > :sql_last_value and time < NOW() ORDER BY time ASC;
