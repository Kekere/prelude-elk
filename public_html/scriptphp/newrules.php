<?php
$file = '/home/mulval/kb/interaction_rules.P';
// Ouvre un fichier pour lire un contenu existant
$current = file_get_contents($file);
// Ajoute une personne
$current .= "\nprimitive(successExploit(_host,_vulID)).
primitive(neededPrivileges(_host,_user)).
derived(gainsPrivileges(_host, _user, _priv)).
:- table gainsPrivileges/3.\n
interaction_rule(
    (gainsPrivileges(Host, Perm, admin) :-
          successExploit('157.159.68.97', 'CVE-2012-0152'),
          networkServiceInfo('157.159.68.97','windows remote_desktop_protocol',tcp,'445',someUser),
          vulExists('157.159.68.97','CVE-2012-0152','windows remote_desktop_protocol',remoteExploit,privEscalation),
          netAccess('157.159.68.97', tcp, 445)),
    rule_desc('Gain Privileges',
    1.0)).\n
  interaction_rule(
    (execCode(Host, Perm) :-
      vulExists('157.159.68.97','CVE-2017-0143','windows',remoteExploit,privEscalation),	
      gainsPrivileges('157.159.68.97',Perm,admin),
      neededPrivileges('157.159.68.97',_),
      networkServiceInfo('157.159.68.97','windows remote_desktop_protocol',tcp,'445',someUser)),
    rule_desc('remote exploit of a server program',
    1.0)).";
// Écrit le résultat dans le fichier
file_put_contents($file, $current);
?>