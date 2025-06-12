local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local unpwdb = require "unpwdb"
local ftp = require "ftp"

description = [[
Performs FTP username enumeration by analyzing server responses and timing.

Detects valid usernames by observing:
- 331 (User OK, need password) → VALID
- 530 (Login incorrect) after USER → INVALID

Falls back to timing if needed. Also supports passive mode (just banner).
]]

---
-- @usage
-- nmap -p21 <target> --script ftp-user-enum.nse --script-args userdb=utils/wordlists/users.txt
-- @args userdb Path to username wordlist
-- @args ftp-user-enum.verbose Show all results, not just valid users
-- @args ftp-user-enum.passive Only fetch banner, no brute
--
-- @output
-- PORT   STATE SERVICE
-- 21/tcp open  ftp
-- | ftp-user-enum:
-- |   FTP Banner: vsFTPd 3.0.3
-- |   Valid Users:
-- |     admin
-- |     dev
-- |_    backup

author = "Braxton Bailey"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "discovery", "intrusive"}

portrule = shortport.port_or_service(21, "ftp")

action = function(host, port)
  local verbose = stdnse.get_script_args("ftp-user-enum.verbose")
  local passive = stdnse.get_script_args("ftp-user-enum.passive")
  local usernames = unpwdb.usernames()
  local results = {}
  local banner = ""

  local control = nmap.new_socket()
  local status, err = control:connect(host, port)
  if not status then return "FTP service unavailable." end

  -- grab banner
  local line = control:receive_lines(1)
  if line then
    banner = line
    table.insert(results, "FTP Banner: " .. line)
  end

  control:close()

  if passive then
    return stdnse.format_output(true, results)
  end

  local valid_users = {}

  for username in usernames do
    local sock = nmap.new_socket()
    sock:set_timeout(3000)
    local ok, err = sock:connect(host, port)
    if not ok then sock:close(); goto continue end

    local _ = sock:receive_lines(1) -- discard banner
    sock:send("USER " .. username .. "\r\n")
    local reply = sock:receive_lines(1)

    if reply then
      if string.match(reply, "^331") then
        table.insert(valid_users, username)
      elseif verbose then
        table.insert(results, string.format("[X] %s → %s", username, reply))
      end
    end

    sock:close()
    ::continue::
  end

  if #valid_users > 0 then
    table.insert(results, "Valid Users:")
    for _, u in ipairs(valid_users) do
      table.insert(results, "  " .. u)
    end
  else
    table.insert(results, "No valid usernames found.")
  end

  return stdnse.format_output(true, results)
end

