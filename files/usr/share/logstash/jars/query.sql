Select DISTINCT prelude_classification._message_ident, time as createtime, prelude_classification.ident, prelude_classification.text, prelude_impact.description, prelude_impact.severity, prelude_impact.completion, prelude_impact.type, prelude_node.name as node_name, prelude_target.interface as target_inteface, prelude_source.interface as source_interface, prelude_userid.type, prelude_userid.name as user_name, prelude_user.category 
from prelude_user inner join prelude_createtime on prelude_user._message_ident=prelude_createtime._message_ident 
inner join prelude_userid on prelude_createtime._message_ident=prelude_userid._message_ident 
inner join prelude_classification on prelude_userid._message_ident=prelude_classification._message_ident 
inner join prelude_impact on prelude_classification._message_ident=prelude_impact._message_ident 
inner join prelude_node on prelude_impact._message_ident=prelude_node._message_ident 
inner join prelude_source on prelude_node._message_ident=prelude_source._message_ident 
inner join prelude_target on prelude_source._message_ident=prelude_target._message_ident 
inner join prelude_address on prelude_target._message_ident=prelude_address._message_ident 
where prelude_createtime._parent_type='A' and time > :sql_last_value and time < NOW() ORDER BY time ASC;
