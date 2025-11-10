GET {{jmxHttpBridgeUrl}}/jolokia/read/org.igniterealtime.openfire:type=Statistic,name=*
Authorization: {{sharedSecret}}
HTTP 200
# [Asserts]
# jsonpath "$.request.mbean" == "org.igniterealtime.openfire:name=*,type=Statistic"
# jsonpath "$.value['org.igniterealtime.openfire:name=muc_incoming,type=Statistic']" exists
# jsonpath "$.value['org.igniterealtime.openfire:name=server_bytes_out,type=Statistic']" exists
# jsonpath "$.value['org.igniterealtime.openfire:name=muc_rooms,type=Statistic']" exists
# jsonpath "$.value['org.igniterealtime.openfire:name=proxyTransferRate,type=Statistic']" exists
# jsonpath "$.value['org.igniterealtime.openfire:name=server_bytes_in,type=Statistic']" exists
# jsonpath "$.value['org.igniterealtime.openfire:name=muc_occupants,type=Statistic']" exists
# jsonpath "$.value['org.igniterealtime.openfire:name=muc_outgoing,type=Statistic']" exists
# jsonpath "$.value['org.igniterealtime.openfire:name=muc_users,type=Statistic']" exists
# jsonpath "$.value.*" count == 8
