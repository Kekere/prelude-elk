from kafka.consumer import KafkaConsumer
from kafka import TopicPartition
import time

try:
    consumer = KafkaConsumer('ctm',bootstrap_servers=['impetus.simavi.ro:9093'],
      security_protocol='SASL_SSL',
      #ssl_check_hostname=True,
      ssl_cafile='/var/www/html/confluent/kafka/config/ca.crt',
      sasl_mechanism="PLAIN",
      sasl_plain_username='ctm',
      sasl_plain_password='mKcC3Uz0EItfXgqrBEqR')
    

except:
     time.sleep(1)
                      
try:                        
    print('Getting Web message .')
    for message in consumer:
         kafkaTxtAreaOut.insert(END,"%s:%d:%d: key=%s value=%s" % (message.topic, message.partition,
                                 message.offset, message.key,message.value))
         pprint.pprint("%s:%d:%d: key=%s \n value=%s" % (message.topic, message.partition,message.offset, message.key,message.value))
    u.kconsumer=True    
except:
    time.sleep(1)  
