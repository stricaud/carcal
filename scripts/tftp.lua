-- tftp.lua — decode TFTP with a posa definition from Lua, on the UDP payload.
-- Shows caracal.decode_as (single dispatched decode) and caracal.decode_all
-- (every candidate way an Object<parent> group can be decoded).
--   caracal -s scripts/tftp.lua -r tftp.pcapng

function packet(pkt)
  if pkt.l4 ~= "udp" or not pkt.payload then return end
  if pkt.dstport ~= 69 and pkt.srcport ~= 69 then return end

  -- the dispatched decode (TFTP group -> the matching message type)
  local f = caracal.decode_as(pkt.payload, "TFTP")
  if f then
    print(string.format("pkt %d: TFTP opcode=%d %s", pkt.number, f.opcode or -1,
          f.filename and ("file=" .. f.filename .. " mode=" .. (f.mode or "")) or ""))
  end

  -- "the various ways the protocol can be decoded": every sub-protocol's view
  for _, way in ipairs(caracal.decode_all(pkt.payload, "TFTP")) do
    print("   could be " .. way.proto .. " -> opcode=" .. tostring(way.fields.opcode))
  end
end
