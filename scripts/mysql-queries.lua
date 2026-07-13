-- mysql-queries.lua — the MQS use-case, generalized and stream-reassembled.
--
-- Reassembled client->server TCP bytes arrive in stream(); we parse MySQL
-- packets (3-byte little-endian length, 1-byte sequence, then payload whose
-- first byte is the command; 0x03 = COM_QUERY) out of the reassembled buffer.
--
--   carcal -s scripts/mysql-queries.lua -r capture.pcapng -f "tcp.port == 3306"
--
-- Unlike MQS this works on any capture file, reassembles segments split across
-- packets, and you could just as well bind a .posa protocol with -X and use
-- carcal.decode_as(s.data, "...") for a binary application protocol.

local COM_QUERY = 0x03

function stream(s)
  if s.dstport ~= 3306 then return end       -- client -> MySQL server only
  local b = s.all                            -- cumulative reassembled bytes
  local pos = 1
  while #b - pos + 1 >= 5 do
    local len = b:byte(pos) + b:byte(pos+1)*256 + b:byte(pos+2)*65536
    if #b - (pos+3) < len then break end     -- message not fully arrived yet
    local cmd = b:byte(pos+4)
    if cmd == COM_QUERY then
      print(os.date("[%H:%M:%S] ") .. b:sub(pos+5, pos+3+len))
    end
    pos = pos + 4 + len
  end
end
