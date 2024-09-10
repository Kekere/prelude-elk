from confluent_kafka import Consumer, KafkaError

settings = {
	'bootstrap.servers': 'impetus.simavi.ro:9093',
	'group.id': 'ctm',
	'client.id': 'ctm',
	'security.protocol': 'SASL_SSL',
	'sasl.mechanisms': 'PLAIN',
	'sasl.username': 'ctm',
	'sasl.password': 'mKcC3Uz0EItfXgqrBEqR',
	'ssl.ca.location': '/home/keren/kafka_2.13-3.1.0/config/ca.crt',
	'enable.auto.commit': True,
	'session.timeout.ms': 6000,
	'default.topic.config': {'auto.offset.reset': 'smallest'}
}

c = Consumer(settings)

c.subscribe(['ctm'])

try:
    while True:
        msg = c.poll(0.1)
        if msg is None:
            continue
        elif not msg.error():
            print('Received message: {0}'.format(msg.value()))
        elif msg.error().code() == KafkaError._PARTITION_EOF:
            print('End of partition reached {0}/{1}'
                  .format(msg.topic(), msg.partition()))
        else:
            print('Error occured: {0}'.format(msg.error().str()))

except KeyboardInterrupt:
    pass

finally:
    c.close()
