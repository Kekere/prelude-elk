from kafka.producer import KafkaProducer
from kafka import TopicPartition
import time

#--producteur

try:
    ssl_produce = KafkaProducer(bootstrap_servers='impetus.simavi.ro:9093',
     security_protocol='SASL_SSL',
     ssl_cafile='/var/www/html/confluent/kafka/config/ca.crt',
     sasl_mechanism="PLAIN",
     sasl_plain_username='ctm',
     sasl_plain_password='mKcC3Uz0EItfXgqrBEqR',
                value_serializer=lambda v: json.dumps(v).encode('utf-8'))
    metrics = ssl_produce.metrics()
    pprint.pprint(metrics)                   

    
except:
    time.sleep(1)

try:                        
    
    ssl_produce.send("ctm",{"ctm": {
        "CVE":"CVE-2019-0708",
        "Description": "Microsoft has released a set of patches for Windows XP, 2003, 2008, 7, and 2008 R2." ,
        "Location": "Oslo" ,
        "Date": datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z')+"+01:00"
        
    }})
    

except:
    time.sleep(1)
