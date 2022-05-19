from kafka import KafkaConsumer

# To consume latest messages and auto-commit offsets
consumer = KafkaConsumer('ctm',group_id='ctm',bootstrap_servers=['impetus.simavi.ro:9093'],
                            security_protocol='SASL_SSL',
                            #ssl_check_hostname=True,
                            ssl_cafile='/home/keren/ca.crt',
                            sasl_mechanism="PLAIN",
                            sasl_plain_username='ctm',
                            sasl_plain_password='mKcC3Uz0EItfXgqrBEqR'
                        )

mypartition = TopicPartition("ctm", 0)
assigned_topic = [smypartition]
consumer.assign(assigned_topic)
consumer.seek_to_beginning(mypartition)

for message in consumer:
    # message value and key are raw bytes -- decode if necessary!
    # e.g., for unicode: `message.value.decode('utf-8')`
    print ("%s:%d:%d: key=%s value=%s" % (message.topic, message.partition,
                                          message.offset, message.key,
                                          message.value))

# consume earliest available messages, don't commit offsets
KafkaConsumer(auto_offset_reset='earliest', enable_auto_commit=False)

# consume json messages
KafkaConsumer(value_deserializer=lambda m: json.loads(m.decode('ascii')))

# consume msgpack
KafkaConsumer(value_deserializer=msgpack.unpackb)

# StopIteration if no message after 1sec
KafkaConsumer(consumer_timeout_ms=1000)

# Subscribe to a regex topic pattern
consumer = KafkaConsumer()
consumer.subscribe(pattern='^awesome.*')

