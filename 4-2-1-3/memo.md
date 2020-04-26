# Address

Description     MAC                 IP
--------------------------------------------------
Attacker        02:42:ac:27:4f:81   10.4.22.208
Client          02:42:ac:41:2a:fe   10.4.22.53
DNS             02:42:ac:78:40:9b   10.4.22.247

# tshark

``` bash
tshark \
    -T fields -c 5000 -i switch \
    -e frame.number \
    -e _ws.col.Source \
    -e _ws.col.Destination \
    -e eth.src \
    -e eth.dst \
    -e _ws.col.Protocol \
    -e tcp.flags \
    -e _ws.col.Info \
    -e http.request.full_uri \
    -f "(ether src 02:42:ac:27:4f:81 and ether dst 02:42:ac:41:2a:fe) or
        (ether src 02:42:ac:41:2a:fe and ether dst 02:42:ac:27:4f:81) and
        (tcp) and 
        (not port 22)
        "
```