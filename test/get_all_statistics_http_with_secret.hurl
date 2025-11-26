GET {{jmxHttpBridgeUrl}}/jolokia/read/org.igniterealtime.openfire:type=Statistic,name=*
Authorization: {{sharedSecret}}
HTTP 200
[Asserts]
jsonpath "$.request.mbean" == "org.igniterealtime.openfire:name=*,type=Statistic"
jsonpath "$.value.*" count > 0
