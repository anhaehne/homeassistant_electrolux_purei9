# homeassistant_electrolux_purei9

Most of the code is taken from: https://github.com/Phype/purei9-cli

The vacuum needs a static ip address. 
Add this to oyu ha config:

``` yaml
vacuum:
  - platform: electrolux_purei9
    name: <vacuum name>
    email: <electroLux/AEG email>
    password: <electroLux/AEG password>
    ip_address: "<static ip of the vacuum>" # example: "192.168.1.123"
```
