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

JSON rule example:
{
    "method":"rule_add",
    "params":{
        "src_ip":"10.0.0.1",
        "dst_ip":"10.0.0.1",
        "proto":"tcp",
        "src_port":80,
        "dst_port":80,
        "action":"ACCEPT"
    }
}

curl -v -X POST -d @add_rule.json http://localhost:8080/api/plugins/rpc/twoway/87276620-f3ae-11ef-96bc-579b3f6f0edd --header "Content-Type:application/json" --header "X-Authorization: Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhbGV4aG9udGFuaWxsYUBnbWFpbC5jb20iLCJ1c2VySWQiOiJkZDZiYTIxMC1mOWZmLTExZWYtOTU5MS1iYjRmNGZiZTQ4MDUiLCJzY29wZXMiOlsiVEVOQU5UX0FETUlOIl0sInNlc3Npb25JZCI6IjdkODg0ODJjLTc3YzMtNDZlOS04MzNjLWU1NzY0MTc5ZGQwNyIsImV4cCI6MTc0MTgyNTYwOSwiaXNzIjoidGhpbmdzYm9hcmQuaW8iLCJpYXQiOjE3NDE4MTY2MDksImVuYWJsZWQiOnRydWUsImlzUHVibGljIjpmYWxzZSwidGVuYW50SWQiOiI3MDEyYjI2MC1mM2FkLTExZWYtOTZiYy01NzliM2Y2ZjBlZGQiLCJjdXN0b21lcklkIjoiMTM4MTQwMDAtMWRkMi0xMWIyLTgwODAtODA4MDgwODA4MDgwIn0.SWD-SNw79ApgEqMzbQFrA29Vy-YYf8_eHYM-pHIiT86z32lnDp3ghjYdTNmFKuJnoPb-sm1ywdKj7nTdnQLP0A"