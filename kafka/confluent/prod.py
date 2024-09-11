from confluent_kafka import Producer
import sys
from confluent_kafka.admin import AdminClient, NewTopic, NewPartitions, ConfigResource, ConfigSource 
from confluent_kafka import Consumer, KafkaException, KafkaError
#from past.builtins import xrange
import time
import json

"""p = Producer({'bootstrap.servers': 'impetus.simavi.ro:9093',
		'security.protocol': 'SASL_SSL',
		'sasl.mechanisms': 'PLAIN',
	    	'sasl.username': 'ctm',
	    	'sasl.password': 'mKcC3Uz0EItfXgqrBEqR',
	    	'ssl.ca.location': '/var/www/html/kafka/ca.crt'})"""

"""ac = AdminClient(p)
md = ac.list_topics()
md.topics
print(md.topics)"""
#p.produce('ctm', key='CVE-2019-0708', value='Microsoft has released a set of patches for Windows XP, 2003, 2008, 7, and 2008 R2.')
#p.flush(30)

jsonString3 = """ {"CVE":"CVE-2019-0708", "Asset":"Olivia", "mitigation": "Microsoft has released a set of patches for Windows XP, 2003, 2008, 7, and 2008 R2."} """
jsonv1 = jsonString3.encode()

def acked(err, msg):
    if err is not None:
        print("Failed to deliver message: {0}: {1}"
              .format(msg.value(), err.str()))
    else:
        print("Message produced: {0}".format(msg.value()))

p = Producer({'bootstrap.servers': 'impetus.simavi.ro:9093',
		'security.protocol': 'SASL_SSL',
		'sasl.mechanisms': 'PLAIN',
	    	'sasl.username': 'ctm',
	    	'sasl.password': 'mKcC3Uz0EItfXgqrBEqR',
	    	'ssl.ca.location': '/home/keren/kafka_2.13-3.1.0/config/ca.crt'})

try:
    for val in xrange(1, 2):
    	
	
        p.produce('ctm', key='Oslo1', value=jsonv1
                  , callback=acked)
        p.poll(0.5)

except KeyboardInterrupt:
    pass

p.flush(30)
