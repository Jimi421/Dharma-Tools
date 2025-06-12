local smb = require "smb"
local stdnse = require "stdnse"
local shortport = require "shortport"
local string = require "string"

description = [[
Performs anonymous SMB share enumeration to identify readable shares
and search recursively for loot files (e.g., credentials, keys, configs).

Highlights:
- Detects sensitive files via regex pattern match
- Recursively scans directories (configurable depth)
- Flags writable shares for potential post-exploitation
- User-defined loot patterns supported
]]

---
-- @usage
-- nmap -p445 <target> --script ./nse/smb-anon-hunter.nse
-- @args smb-anon-hunter.depth    Max recursion depth (default: 3)
-- @args smb-anon-hunter.patterns Comma-separated regex patterns for loot (e.g. %.key$,%.conf$)
-- @args smb-anon-hunter.verbose  Show all shares even if no loot found
--
-- @output
-- PORT    STATE SERVICE
-- 445/tcp open  microsoft-ds
-- | smb-anon-hunter:
-- |   Writable Share: public
-- |   Loot:
-- |     Share: public
-- |       /creds.env (size: 32 bytes, mtime: 2024-03-14 10:21)
-- |       /keys/id_rsa (size: 1675 bytes, mtime: 2023-12-08 09:55)
-- |_  Done.

author = "Braxton Bailey"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "auth", "intrusive"}

portrule = shortport.port_or_service(445, "microsoft-ds")

-- Default loot file patterns
local default_patterns = {
  "%.env$", "%.key$", "%.pem$", "%.conf$", "%.yml$",
  "%.ini$", "%.cfg$", "%.sql$", "id_rsa$", "%.bak$", "%.json$"
}

-- Recursive walk function
function walk(smbstate, share, path, depth, maxdepth, loot)
  if depth > maxdepth then return end
  local files = smbstate:get_dir(path)
  if not files then return end

  for _, file in ipairs(files) do
    local fullpath = (path == "" and "" or path .. "/") .. file.name
    if file.is_directory then
      walk(smbstate, share, fullpath, depth + 1, maxdepth, loot)
    else
      for _, pattern in ipairs(loot.patterns) do
        if string.match(file.name:lower(), pattern) then
          table.insert(loot.found, {
            share = share,
            path = fullpath,
            size = file.size or "n/a",
            mtime = file.mtime or "unknown"
          })
        end
      end
    end
  end
end

action = function(host, port)
  local result = {}
  local loot = { found = {}, patterns = {} }

  -- Grab script args
  local maxdepth = tonumber(stdnse.get_script_args("smb-anon-hunter.depth")) or 3
  local pattern_arg = stdnse.get_script_args("smb-anon-hunter.patterns")
  local verbose = stdnse.get_sc_

