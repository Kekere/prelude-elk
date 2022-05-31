from kafka import KafkaProducer
from kafka.errors import KafkaError
import json

producer = KafkaProducer(bootstrap_servers='impetus.simavi.ro:9093',
     security_protocol='SASL_SSL',
     ssl_cafile='/var/www/html/confluent/kafka/config/ca.crt',
     sasl_mechanism="PLAIN",
     sasl_plain_username='ctm',
     sasl_plain_password='mKcC3Uz0EItfXgqrBEqR',
     value_serializer=lambda m: json.dumps(m).encode('ascii'))
# Opening JSON file
f = open('../general.json')
  
# returns JSON object as 
# a dictionary
data = json.load(f)
# Asynchronous by default
future = producer.send("ctm", data)

# Block for 'synchronous' sends
try:
    record_metadata = future.get(timeout=10)
except KafkaError:
    # Decide what to do if produce request failed...
    log.exception()
    pass

# Successful result returns assigned partition and offset
print (record_metadata.topic)
print (record_metadata.partition)
print (record_metadata.offset)


# block until all async messages are sent
producer.flush()