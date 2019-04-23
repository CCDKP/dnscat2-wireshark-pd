-- Wireshark PostDissector to ascii decode non-passworded DNScat2 traffic.
-- Based off the dnscat dissector by DiabloHorn https://diablohorn.wordpress.com
-- Currently only performs ascii decode, should be expanded to include the rest of the protocol
 
-- info
print("dnscat postdissector loading")

dc_udp_dport = Field.new("udp.dstport")
dc_udp_sport = Field.new("udp.srcport")

-- we need these fields from the dns packets
dc_dns_name = Field.new("dns.qry.name")
dc_dns_resp_type = Field.new("dns.resp.type")
dc_dns_resp_cname = Field.new("dns.cname")
dc_dns_resp_mx = Field.new("dns.mx.mail_exchange")
dc_dns_resp_txt = Field.new("dns.txt")

-- declare our postdissector
dnscat = Proto("DNSCat","DNSCat postdissector") 
 
-- our fields
dc_rawrequest = ProtoField.string("dnscat.rawreq","Encoded Dnscat Request")
dc_rawresponse = ProtoField.string("dnscat.rawresp","Encoded Dnscat Response")
dc_data = ProtoField.string("dnscat.data","Decoded Data")
dc_length = ProtoField.uint32("dnscat.len","Length of Decoded Data")

-- add our fields
dnscat.fields = {dc_rawrequest,dc_rawresponse,dc_data,dc_length}
 
-- dissect each packet
function dnscat.dissector(buffer,pinfo,tree)
 local udpsport = dc_udp_sport()
 local udpdport = dc_udp_dport()
 local dnsqryname = dc_dns_name()
 local dnstype = dc_dns_resp_type()
 local dnsresp
 local length = 0

 -- don't parse non-dns data
 if not dnsqryname then
 return
 end
 
 if tostring(dnstype) == "15" then
 dnsresp = dc_dns_resp_mx()
 end
 if tostring(dnstype) == "16" then
 dnsresp = dc_dns_resp_txt()
 end
 if tostring(dnstype) == "5" then
 dnsresp = dc_dns_resp_cname()
 end

 -- Quick sanity check that the query has enough data to be a valid command
 local lencheck = getdata(tostring(dnsqryname))
 if string.len(lencheck) < 18 then
 return
 end

 local subtree = tree:add(dnscat,"DNSCat Data")
 local parsed = {}

 if tostring(udpdport) == "53" then
 subtree:add(dc_rawrequest,tostring(dnsqryname))
 parsed = parseDC(tostring(dnsqryname))
 end
 
 if tostring(udpsport) == "53" then
 subtree:add(dc_rawresponse,tostring(dnsresp))
 parsed = parseDC(tostring(dnsresp))
 end
 
 subtree:add(dc_data,tostring(parsed))
 length = string.len(parsed)
 subtree:add(dc_length,length)
 
end -- end dissector function
 
-- Clean up data
function getdata(data)
 -- strip off dnscat. prefix if present
 data = data:gsub("dnscat.", "")
 for sub in data:gmatch("[^%.]+") do
 -- return first subdomain only
 return sub
 end
end
 
-- decode hex data to ascii
function decodehex(data)
 local dec = ""
 for sub in data:gmatch("%x%x") do
 local decnum = tonumber(sub,16)
 if decnum > 31 and decnum < 127 then
 dec = dec .. string.char(decnum)
 else
 dec = dec .. "."
 end
 end
 return dec
end

-- Should be expanded to handle the full protocol, but ascii works
function parseDC(data)
 local x = getdata(data)
 -- Discard first 19 prococol characters, leaving only ascii commands
 cmd = x:sub(19)
 return decodehex(cmd)
end 
 
-- register ourselfs
register_postdissector(dnscat)