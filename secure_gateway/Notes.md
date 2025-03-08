The features extracted of the packets are as follows:

IP Layer:

Total data length: The data sent could be an indication of attack (DoS)
IP source
IP destiny

Control Layer Protocol:

Protocol
Source Port
Destiny port

Thingsboard device:

ClientID: 1234
UserName: tfmtest
Password: tfmtest

Test Command: mosquitto_pub -d -q 1 -h localhost -p 1883 -t v1/devices/me/telemetry -i "1234" -u "tfmtest" -P "tfmtest" -m "{temperature:25}"

Server side RPC:
curl -v -X POST -d @set-gpio-request.json http://localhost:8080/api/plugins/rpc/twoway/<device_id> --header "Content-Type:application/json" --header "X-Authorization: Bearer $JWTToken"

Get JWTToken:

curl -X POST --header 'Content-Type: application/json' --header 'Accept: application/json' -d '{"username":"alexhontanilla@gmail.com", "password":"Ahbgs2000"}' 'http://localhost:8080/api/auth/login'

Get Time-series keys:

curl -v -X GET http://localhost:8080/api/plugins/telemetry/DEVICE/<device_id>/keys/timeseries --header "Content-Type:application/json" --header "X-Authorization: Bearer $JWTToken"

Get time-series data for key

curl -v -X GET http://localhost:8080/api/plugins/telemetry/DEVICE/<device_id>/values/timeseries?keys=<keys> --header "Content-Type:application/json" --header "X-Authorization: Bearer $JWTToken"

RPC: 

mosquitto_sub -d -q 1 -h localhost -p 1883 -t v1/devices/me/rpc/request/+ -i "1234" -u "tfmtest" -P "tfmtest"