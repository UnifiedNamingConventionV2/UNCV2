--#[[ UNC V2 ENVIRONMENT CHECK ]]#--
--#[[ contact @norby.dev_ on discord if there are any issues present ]]#--
--#[[ Special thanks to vxsty for printidentity check and the synapse x team for debug function check ]]#--
local passes, fails, undefined, running, cclosureamount, lclosureamount = 0, 0, 0, 0, 0, 0

local function getGlobal(path)
    local value = getfenv(0)

    while value ~= nil and path ~= "" do
        local name, nextValue = string.match(path, "^([^.]+)%.?(.*)$")
        value = value[name]
        path = nextValue
    end

    return value
end

local function test(name, aliases, callback, func)
    running = running + 1

    task.spawn(function()
        if name == "script" then
            local success, message = pcall(function() return script ~= nil end)
            if success then
                -- not a function so no closure checking
                local pass, fail = pcall(function()
                    assert(script.Parent == nil, "Source script should be parented to nil");
                end)
                if pass then
                    passes = passes + 1
                    print("✅ " .. name .. "")
                else
                    fails = fails + 1
                    warn("⛔ " .. name .. " failed: " .. fail)
                end
            else
                fails = fails + 1
                warn("⛔ " .. name)
            end
            running = running - 1
            return;
        elseif not callback then
            print("⏺️ " .. name)
        elseif not getGlobal(name) then
            fails = fails + 1
            warn("⛔ " .. name)
        else
            local success, message = pcall(callback)
            local res;
            if func then
                if iscclosure then
                    -- callback is the test function whoops
                    if iscclosure(func) then
                        cclosureamount = cclosureamount + 1
                    else
                        lclosureamount = lclosureamount + 1
                    end
                    res = (iscclosure(func) and "C closure") or "Lua closure"
                else
                    local function iscclosures(arg1)
                        if debug.info(arg1, 's') == "[C]" then
                            return true
                        else
                            return false
                        end
                    end
                    if iscclosures(func) then
                        cclosureamount = cclosureamount + 1
                    else
                        lclosureamount = lclosureamount + 1
                    end
                    res = (iscclosures(func) and "C closure") or "Lua closure"
                end
            end
            if res then
                if success then
                    passes = passes + 1
                    print("✅ " .. name .. (message and " • " .. message or "") .. " - " .. res)
                else
                    fails = fails + 1
                    warn("⛔ " .. name .. " failed: " .. message .. " - " .. res)
                end
            else
                if success then
                    passes = passes + 1
                    print("✅ " .. name .. (message and " • " .. message or ""))
                else
                    fails = fails + 1
                    warn("⛔ " .. name .. " failed: " .. message)
                end
            end
        end

        local undefinedAliases = {}

        for _, alias in ipairs(aliases) do
            if getGlobal(alias) == nil then
                table.insert(undefinedAliases, alias)
            end
        end

        if #undefinedAliases > 0 then
            undefined = undefined + 1
            warn("⚠️ " .. table.concat(undefinedAliases, ", "))
        end

        running = running - 1
    end)
end

-- Header and summary
print("\n")
print("UNC V2 Environment Check")
print("✅ - Pass, ⛔ - Fail, ⏺️ - No test, ⚠️ - Missing aliases\n")

task.defer(function()
    repeat task.wait() until running == 0

    local rate = math.round(passes / (passes + fails) * 100)
    local outOf = passes .. " out of " .. (passes + fails)
    print("\n")
    print("UNC V2 Environment Check Summary")
    print("✅ Completed all function tests with a " .. rate .. "% success rate (" .. outOf .. ")")
    print("⛔ " .. fails .. " function tests failed")
    print("⚠️ " .. undefined .. " function globals are missing aliases")
    print("ℹ️ " .. cclosureamount .. "% of functions are C closures")
    print("ℹ️ " .. lclosureamount .. "% of functions are Lua closures")
end)

-- Cache

test("cache.invalidate", {}, function()
    local container = Instance.new("Folder")
    local part = Instance.new("Part", container)
    cache.invalidate(container:FindFirstChild("Part"))
    assert(part ~= container:FindFirstChild("Part"), "Reference `part` could not be invalidated")
end, cache.invalidate)

test("cache.iscached", { "cache.cached" }, function()
    local part = Instance.new("Part")
    assert(cache.iscached(part), "Part should be cached")
    cache.invalidate(part)
    assert(not cache.iscached(part), "Part should not be cached")
end, cache.iscached)

test("cache.replace", {}, function()
    local part = Instance.new("Part")
    local fire = Instance.new("Fire")
    cache.replace(part, fire)
    assert(part ~= fire, "Part was not replaced with Fire")
end, cache.replace)

test("cloneref", { "clonereference" }, function()
    local part = Instance.new("Part")
    local clone = cloneref(part)
    assert(part ~= clone, "Clone should not be equal to original")
    clone.Name = "Test"
    assert(part.Name == "Test", "Clone should have updated the original")
    assert(typeof(clone) == typeof(part), "Clone should be the same type instance as part")
end, cloneref)

test("compareinstances", {}, function()
    local part = Instance.new("Part")
    local clone = cloneref(part)
    assert(part ~= clone, "Clone should not be equal to original")
    assert(compareinstances(part, clone), "Clone should be equal to original when using compareinstances()")
end, compareinstances)

local function shallowEqual(t1, t2)
    if t1 == t2 then
        return true
    end

    local UNIQUE_TYPES = {
        ["function"] = true,
        ["table"] = true,
        ["userdata"] = true,
        ["thread"] = true,
    }

    for k, v in pairs(t1) do
        if UNIQUE_TYPES[type(v)] then
            if type(t2[k]) ~= type(v) then
                return false
            end
        elseif t2[k] ~= v then
            return false
        end
    end

    for k, v in pairs(t2) do
        if UNIQUE_TYPES[type(v)] then
            if type(t2[k]) ~= type(v) then
                return false
            end
        elseif t1[k] ~= v then
            return false
        end
    end

    return true
end

test("checkcaller", {}, function()
    assert(checkcaller(), "Main scope should return true")
end, checkcaller)

test("clonefunction", {}, function()
    local function test()
        return "success"
    end
    local copy = clonefunction(test)
    assert(test() == copy(), "The clone should return the same value as the original")
    assert(test ~= copy, "The clone should not be equal to the original")
end, clonefunction)

test("getcallingscript", { "getcaller" }, function()
    assert(getcallingscript() == script, "Caller script should be the same as current script")
end, getcallingscript)

test("getscriptclosure", { "getscriptfunction" }, function()
    local module = game:GetService("CoreGui").RobloxGui.Modules.Common.Constants
    local constants = getrenv().require(module)
    local generated = getscriptclosure(module)()
    assert(constants ~= generated, "Generated module should not match the original")
    assert(shallowEqual(constants, generated), "Generated constant table should be shallow equal to the original")
end, getscriptclosure)

test("hookfunction", { "replaceclosure" }, function()
    local function test()
        return true
    end
    local ref = hookfunction(test, function()
        return false
    end)
    assert(test() == false, "Function should return false")
    assert(ref() == true, "Original function should return true")
    assert(test ~= ref, "Original function should not be same as the reference")
end, hookfunction)

test("iscclosure", {}, function()
    assert(iscclosure(print) == true, "Function 'print' should be a C closure")
    assert(iscclosure(function() end) == false, "Executor function should not be a C closure")
end, iscclosure)

test("islclosure", {}, function()
    assert(islclosure(print) == false, "Function 'print' should not be a Lua closure")
    assert(islclosure(function() end) == true, "Executor function should be a Lua closure")
end, islclosure)

test("isexecutorclosure", { "checkclosure", "isourclosure", "isexploitclosure" }, function()
    assert(isexecutorclosure(isexecutorclosure) == true, "isexecutorclosure did not return true for an executor global")
    assert(isexecutorclosure(newcclosure(function() end)) == true,
        "isexecutorclosure did not return true for an executor C closure")
    assert(isexecutorclosure(function() end) == true,
        "isexecutorclosure did not return true for an executor Luau closure")
    assert(isexecutorclosure(print) == false, "isexecutorclosure did not return false for a Roblox global")
end, isexecutorclosure)

test("loadstring", {}, function()
    if getscriptbytecode then
        local animate = game:GetService("Players").LocalPlayer.Character.Animate
        local bytecode = getscriptbytecode(animate)
        local func = loadstring(bytecode)
        assert(type(func) ~= "function", "Luau bytecode should not be loadable!")
        assert(assert(loadstring("return ... + 1"))(1) == 2, "loadstring failed to load Lua code")
        assert(type(select(2, loadstring("f"))) == "string", "loadstring did not return anything for a compiler error")
    else
        local func = loadstring("getgenv().UNCtest = 1")
        if getgenv().UNCtest then
            assert(false, "loadstring should return a function to be called")
        end
        assert(type(func) == "function", "loadstring did not return a function")
        local a, b = pcall(func)
        assert(a, "loadstring failed to load Lua code")
        assert(getgenv().UNCtest, "loadstring failed to load Lua code and did not return a error")
        getgenv().UNCtest = nil
    end
end, loadstring)

test("newcclosure", {}, function()
    local function test()
        return true
    end
    local testC = newcclosure(test)
    assert(test() == testC(), "New C closure should return the same value as the original")
    assert(test ~= testC, "New C closure should not be same as the original")
    assert(iscclosure(testC), "New C closure should be a C closure")
end, newcclosure)

test("rconsoleclear", { "consoleclear" }, nil, rconsoleclear)

test("rconsolecreate", { "consolecreate" }, nil, rconsolecreate)

test("rconsoledestroy", { "consoledestroy" }, nil, rconsoledestroy)

test("rconsoleinput", { "consoleinput" }, nil, rconsoleinput)

test("rconsoleprint", { "consoleprint" }, nil, rconsoleprint)

test("rconsolesettitle", { "rconsolename", "consolesettitle", "consoletitle" }, rconsolesettitle)

test("crypt.base64encode", { "crypt.base64.encode", "crypt.base64_encode", "base64.encode", "base64_encode" }, function()
    assert(crypt.base64encode("test") == "dGVzdA==", "Base64 encoding failed")
    assert(crypt.base64encode("hello") == "aGVsbG8=", "Base64 encoding failed")
end, crypt.base64encode)

test("crypt.base64decode", { "crypt.base64.decode", "crypt.base64_decode", "base64.decode", "base64_decode" }, function()
    assert(crypt.base64decode("dGVzdA==") == "test", "Base64 decoding failed")
    assert(crypt.base64decode("aGVsbG8=") == "hello", "Base64 decoding failed")
end, crypt.base64decode)

test("crypt.encrypt", {}, function()
    local key = crypt.generatekey()
    local encrypted, iv = crypt.encrypt("test", key, nil, "CBC")
    assert(iv, "crypt.encrypt should return an IV")
    local decrypted = crypt.decrypt(encrypted, key, iv, "CBC")
    assert(decrypted == "test", "Failed to decrypt raw string from encrypted data")
end, crypt.encrypt)

test("crypt.decrypt", {}, function()
    local key, iv = crypt.generatekey(), crypt.generatekey()
    local encrypted = crypt.encrypt("test", key, iv, "CBC")
    local decrypted = crypt.decrypt(encrypted, key, iv, "CBC")
    assert(decrypted == "test", "Failed to decrypt raw string from encrypted data")
end, crypt.decrypt)

test("crypt.generatebytes", {}, function()
    local size = math.random(10, 100)
    local bytes = crypt.generatebytes(size)
    assert(#crypt.base64decode(bytes) == size,
        "The decoded result should be " ..
        size .. " bytes long (got " .. #crypt.base64decode(bytes) .. " decoded, " .. #bytes .. " raw)")
end, crypt.generatebytes)

test("crypt.generatekey", {}, function()
    local key = crypt.generatekey()
    assert(#crypt.base64decode(key) == 32, "Generated key should be 32 bytes long when decoded")
end, crypt.generatekey)

test("crypt.hash", {}, function()
    local algorithms = { 'sha1', 'sha384', 'sha512', 'md5', 'sha256', 'sha3-224', 'sha3-256', 'sha3-512' }
    for _, algorithm in ipairs(algorithms) do
        local hash = crypt.hash("test", algorithm)
        assert(hash, "crypt.hash on algorithm '" .. algorithm .. "' should return a hash")
    end
end, crypt.hash)

--- Debug

test("debug.getregistry", { "getregistry", "getreg", "debug.getreg" }, function()
    assert(typeof(debug.getregistry()) == "table", "debug.getregistry did not return a table")
    assert(#debug.getregistry() ~= 0, "debug.getregistry returned a empty table")
end, debug.getregistry)

test("debug.getconstant", { "getconstant", "getconst", "debug.getconst" }, function()
    local function test()
        print("Hello, world!")
    end
    assert(debug.getconstant(test, 1) == "print", "First constant must be print")
    assert(debug.getconstant(test, 2) == nil, "Second constant must be nil")
    assert(debug.getconstant(test, 3) == "Hello, world!", "Third constant must be 'Hello, world!'")
    if debug.getconstants then
        assert(not pcall(function()
            local size = #debug.getconstants(x); debug.getconstant(x, size + 1)
        end), "debug.getconstant must check constant bounds")
    end
end, debug.getconstant)

test("debug.getconstants", { "getconstants", "getconsts", "debug.getconsts" }, function()
    local function test()
        local num = 5000 .. 50000
        print("Hello, world!", num, warn)
    end
    local constants = debug.getconstants(test)
    assert(constants[1] == 50000, "First constant must be 50000")
    assert(constants[2] == "print", "Second constant must be print")
    assert(constants[3] == nil, "Third constant must be nil")
    assert(constants[4] == "Hello, world!", "Fourth constant must be 'Hello, world!'")
    assert(constants[5] == "warn", "Fifth constant must be warn")
end, debug.getconstants)

test("debug.getinfo", { "debug.getfunctioninfo", "debug.getfuncinfo" }, function()
    local types = {
        source = "string",
        short_src = "string",
        func = "function",
        what = "string",
        currentline = "number",
        name = "string",
        nups = "number",
        numparams = "number",
        is_vararg = "number",
    }
    local function test(...)
        print(...)
    end
    local info = debug.getinfo(test)
    for k, v in pairs(types) do
        assert(info[k] ~= nil, "debug.getinfo did not return a table with a '" .. k .. "' field")
        assert(type(info[k]) == v,
            "debug.getinfo did not return a table with " .. k .. " as a " .. v .. " (got " .. type(info[k]) .. ")")
    end
end, debug.getinfo)

test("debug.getproto", { "getproto" }, function()
    local function test()
        local function proto()
            return true
        end
    end
    local proto = debug.getproto(test, 1, true)[1]
    local realproto = debug.getproto(test, 1)
    assert(proto, "Failed to get the inner function")
    assert(proto() == true, "The inner function did not return a value")
    if not realproto() then
        return "Proto return values are disabled on this executor"
    end
    local function a()
        local function b()
            return 123
        end

        b()
    end

    assert(not pcall(function() debug.getproto(-1, 1) end), "debug.getproto must not allow negative numbers")

    local proto = debug.getproto(a, 1)
    local _, result = pcall(function() return proto() end)

    if result == 123 then
        assert(false, "debug.getproto should not allow calling the resulting function")
    end
end, debug.getproto)

test("debug.getprotos", { "getprotos" }, function()
    local function test()
        local function _1()
            return true
        end
        local function _2()
            return true
        end
        local function _3()
            return true
        end
    end
    for i in ipairs(debug.getprotos(test)) do
        local proto = debug.getproto(test, i, true)[1]
        local realproto = debug.getproto(test, i)
        assert(proto(), "Failed to get inner function " .. i)
        if not realproto() then
            return "Proto return values are disabled on this executor"
        end
    end

    local function a()
        local function b()
            return 123
        end
        b()
    end

    local protos = debug.getprotos(a)
    assert(#protos == 1, "debug.getprotos is returning an invalid amount of prototypes")

    local _, result = pcall(function() return protos[1]() end)
    if result == 123 then
        assert(false, "debug.getprotos allows calling the resulting function")
    end
end, debug.getprotos)

test("debug.getstack", {}, function()
    local _ = "a" .. "b"
    assert(debug.getstack(1, 1) == "ab", "The first item in the stack should be 'ab'")
    assert(debug.getstack(1)[1] == "ab", "The first item in the stack table should be 'ab'")
    assert(not pcall(function() debug.getstack(1, 0) end), "getstack must be one based")
    assert(not pcall(function()
        local size = #debug.getstack(1); debug.getstack(1, size + 1)
    end), "debug.getstack bounds")
    if newcclosure then
        assert(not pcall(function() newcclosure(function() debug.getstack(2, 1) end)() end),
            "debug.getstack must not allow reading the stack from C functions")
    end
end, debug.getstack)

test("debug.getupvalue", { "getupvalue", "getupval" }, function()
    local upvalue = function() end
    local function test()
        print(upvalue)
    end
    local upvalue = 1
    local function test2()
        print(upvalue)
        upvalue = 124
    end
    assert(debug.getupvalue(test, 1) == upvalue, "Unexpected value returned from debug.getupvalue")
    assert(not pcall(function() debug.getupvalue(-1, 1) end), "debug.getupvalue must not allow negative numbers")
    assert(not pcall(function() debug.getupvalue(test2, 2) end), "debug.getupvalue must check upvalue bounds")
end, debug.getupvalue)

test("debug.getupvalues", { "getupvalues", "getupvals", "debug.getupvals" }, function()
    local upvalue = function() end
    local function test()
        print(upvalue)
    end
    local upvalues = debug.getupvalues(test)
    assert(upvalues[1] == upvalue, "Unexpected value returned from debug.getupvalues")
    assert(not pcall(function() debug.getupvalues(-1) end), "getupvalues must not allow negative numbers")
end, debug.getupvalues)

test("debug.setconstant", { "setconst", "setconstants", "debug.setconstants", "debug.setconsts" }, function()
    local function test()
        return "fail"
    end
    debug.setconstant(test, 1, "success")
    assert(test() == "success", "debug.setconstant did not set the first constant")
    assert(not pcall(function() debug.setconstant(x, -1, nil) end), "debug.setconstant must not allow negative numbers")
    assert(not pcall(function()
        local size = #debug.getconstants(x); debug.setconstant(x, size + 1, nil)
    end), "debug.setconstant must check constant bounds")
end, debug.setconstant)

test("debug.setstack", {}, function()
    local function test()
        return "fail", debug.setstack(1, 1, "success")
    end
    assert(test() == "success", "debug.setstack did not set the first stack item")

    assert(not pcall(function() debug.setstack(1, 0, nil) end), "setstack must be one based")
    assert(not pcall(function() debug.setstack(1, -1, nil) end), "setstack must not allow negative numbers")
    assert(not pcall(function()
        local size = #debug.getstack(1); debug.setstack(1, size + 1, "")
    end), "debug.setstack must check bounds")
    if newcclosure then
        assert(not pcall(function() newcclosure(function() debug.setstack(2, 1, nil) end)() end),
            "debug.setstack must not allow C functions to have stack values set")
    end
    assert(not pcall(function()
            local a = 1
            debug.setstack(1, 1, true)
        end),
        "debug.setstack must check if the target type is the same (block writing stack if the source type does not match the target type)")
end, debug.setstack)

test("debug.setupvalue", { "setupvalue", "setupvals", "setupval", "debug.setupval", "debug.setupvals" }, function()
    local function upvalue()
        return "fail"
    end
    local function test()
        return upvalue()
    end

    debug.setupvalue(test, 1, function()
        return "success"
    end)

    local upvalue = 1
    local function test2()
        print(upvalue)
        upvalue = 124
    end

    assert(test() == "success", "debug.setupvalue did not set the first upvalue")
    assert(not pcall(function() debug.setupvalue(test2, -1, nil) end), "debug.setupvalue must not allow negative numbers")
    assert(not pcall(function() debug.setupvalue(test2, 2, nil) end), "debug.setupvalue must check upvalue bounds")
    assert(not pcall(function() debug.setupvalue(game.GetChildren, 1, nil) end),
        "debug.setupvalue must not allow C functions to have upvalues set")
end, debug.setupvalue)

-- Filesystem

if isfolder and makefolder and delfolder or fs.isfolder and fs.makefolder and fs.delfolder then
    if isfolder(".tests") then
        delfolder(".tests")
    end
    makefolder(".tests")
end

test("fs", { "filesystem" })

test("fs.readfile", { "readfile" }, function()
    fs.writefile(".tests/readfile.txt", "success")
    assert(fs.readfile(".tests/readfile.txt") == "success", "fs.readfile did not return the contents of the file")
end, fs.readfile)

test("fs.listfiles", { "listfiles" }, function()
    fs.makefolder(".tests/listfiles")
    fs.writefile(".tests/listfiles/test_1.txt", "success")
    fs.writefile(".tests/listfiles/test_2.txt", "success")
        
    local files = fs.listfiles(".tests/listfiles")
    assert(#files == 2, "fs.listfiles did not return the correct number of files")
    assert(fs.isfile(files[1]), "fs.listfiles did not return a file path")
    assert(fs.readfile(files[1]) == "success", "fs.listfiles did not return the correct files")
        
    fs.makefolder(".tests/listfiles_2")
    fs.makefolder(".tests/listfiles_2/test_1")
    fs.makefolder(".tests/listfiles_2/test_2")
    local folders = fs.listfiles(".tests/listfiles_2")
    assert(#folders == 2, "fs.listfiles did not return the correct number of folders")
    assert(fs.isfolder(folders[1]), "fs.listfiles did not return a folder path")

    local success, files = pcall(fs.listfiles, "C:/")

    assert(not (success and #files > 0), "fs can be used to access any directory")
end, fs.listfiles)

test("fs.writefile", { "writefile" }, function()
    fs.writefile(".tests/writefile.txt", "success")
    assert(fs.readfile(".tests/writefile.txt") == "success", "fs.writefile did not write the file")
    local requiresFileExt = pcall(function()
        fs.writefile(".tests/writefile", "success")
        assert(fs.isfile(".tests/writefile.txt"))
    end)
        
    local tryWriteExe = pcall(fs.writefile, ".tests/maliciousfile.exe", "")
    local tryBypassExe = pcall(fs.writefile, ".tests/maliciousfile.eXe", "")
    local tryDirTraversal = pcall(fs.writefile, ".tests/../../UNC2.txt", "If you see this, it means your executor allows directory traversal via ../")

    assert(not tryWriteExe, "fs.writefile allows exe files to be written or does not throw an error")
    assert(not tryBypassExe, "fs.writefile blocks certain file types, but it can be bypassed")
    assert(not tryDirTraversal, "fs.writefile blocks certain file types, but it can be bypassed")
    
    if not requiresFileExt then
        return "This executor requires a file extension in writefile"
    end
end, fs.writefile)

test("fs.makefolder", { "makefolder" }, function()
    fs.makefolder(".tests/makefolder")
    assert(fs.isfolder(".tests/makefolder"), "fs.makefolder did not create the folder")
end, fs.makefolder)

test("fs.appendfile", { "appendfile" }, function()
    fs.writefile(".tests/appendfile.txt", "su")
    fs.appendfile(".tests/appendfile.txt", "cce")
    fs.appendfile(".tests/appendfile.txt", "ss")
    assert(fs.readfile(".tests/appendfile.txt") == "success", "fs.appendfile did not append the file")
end, fs.appendfile)

test("fs.isfile", { "isfile" }, function()
    fs.writefile(".tests/isfile.txt", "success")
    assert(fs.isfile(".tests/isfile.txt") == true, "fs.isfile did not return true for a file")
    assert(fs.isfile(".tests") == false, "fs.isfile did not return false for a folder")
    assert(fs.isfile(".tests/doesnotexist.exe") == false,
        "fs.isfile did not return false for a nonexistent path (got " ..
        tostring(fs.isfile(".tests/doesnotexist.exe")) .. ")")
end, fs.isfile)

test("fs.isfolder", { "isfolder" }, function()
    assert(fs.isfolder(".tests") == true, "fs.isfolder did not return false for a folder")
    assert(fs.isfolder(".tests/doesnotexist.exe") == false,
        "fs.isfolder did not return false for a nonexistent path (got " ..
        tostring(fs.isfolder(".tests/doesnotexist.exe")) .. ")")
end, fs.isfolder)

test("fs.delfolder", { "delfolder" }, function()
    fs.makefolder(".tests/delfolder")
    fs.delfolder(".tests/delfolder")
    assert(fs.isfolder(".tests/delfolder") == false,
        "fs.delfolder failed to delete folder (isfolder = " .. tostring(fs.isfolder(".tests/delfolder")) .. ")")
end, fs.delfolder)

test("fs.delfile", { "delfile" }, function()
    fs.writefile(".tests/delfile.txt", "Hello, world!")
    fs.delfile(".tests/delfile.txt")
    assert(fs.isfile(".tests/delfile.txt") == false,
        "fs.delfile failed to delete file (isfile = " .. tostring(fs.isfile(".tests/delfile.txt")) .. ")")
end, fs.delfile)

test("fs.loadfile", { "loadfile" }, function()
    fs.writefile(".tests/loadfile.txt", "return ... + 1")
    assert(assert(fs.loadfile(".tests/loadfile.txt"))(1) == 2, "fs.loadfile failed to load a file with arguments")
    fs.writefile(".tests/loadfile.txt", "f")
    local callback, err = fs.loadfile(".tests/loadfile.txt")
    assert(err and not callback, "fs.loadfile did not return an error message for a compiler error")
end, fs.loadfile)

test("fs.dofile", { "dofile" }, function()
    -- https://www.lua.org/pil/8.html
    -- basically loadstring/loadfile without the extension call lol
    fs.writefile(".tests/dofile.txt", "return 1")
    assert(typeof(fs.dofile(".tests/dofile.txt")) == "number",
        "dofile should not return a function; instead execute code directly")
    assert(fs.dofile ~= fs.loadfile, "dofile should not be the same as loadfile")
    assert(fs.dofile(".tests/dofile.txt") == 1, "dofile did not return the correct result")
    writefile(".tests/loadfile.txt", "false")
    assert(pcall(fs.dofile, ".tests/loadfile.txt"), "dofile should return a error if script fails to execute")
end, fs.dofile)

-- Input

test("isrbxactive", { "isgameactive" }, function()
    assert(type(isrbxactive()) == "boolean", "isrbxactive did not return a boolean value")
end, isrbxactive)

test("mouse1click", {}, nil, mouse1click)

test("mouse1press", {}, nil, mouse1press)

test("mouse1release", {}, nil, mouse1release)

test("mouse2click", {}, nil, mouse2click)

test("mouse2press", {}, nil, mouse2press)

test("mouse2release", {}, nil, mouse2release)

test("mousemoveabsolute", { "mousemoveabs" }, nil, mousemoveabsolute)

test("mousemoverelative", { "mousemoverel" }, nil, mousemoverelative)

test("mousescroll", {}, nil, mousescroll)

-- Instances

test("getnamecallmethod", { "getncm", "get_namecall_method"}, function()
    pcall(function()
        game:NAMECALL_METHODS_ARE_IMPORTANT()
    end)

    assert(getnamecallmethod() == "NAMECALL_METHODS_ARE_IMPORTANT", "getnamecallmethod did not return the real namecall method")
end, getnamecallmethod)

test("setnamecallmethod", { "setncm", "set_namecall_method"}, function()
    assert(getrawmetatable, "setnamecallmethod cannot be tested due to getrawmetatable not existing")
    
    pcall(function()
        game:THIS_METHOD_IS_FALSE()
    end)

    assert(getnamecallmethod() == "THIS_METHOD_IS_FALSE", "setnamecallmethod did not return the real namecall method")

    setnamecallmethod("GetService")

    local success, error = pcall(getrawmetatable(game).__namecall, game, "Workspace")

    assert(success, "setnamecallmethod changed the method visible to getnamecallmethod, but __namecall cannot be used due to " .. error)
end, setnamecallmethod)

test("firesignal", {}, function()
    local event = Instance.new("BindableEvent")
    local signal, connection = event.Event, nil
    local result = false
    
    connection = signal:Connect(function(arg)
        result = arg
        connection:Disconnect()
    end)
    
    firesignal(signal, true)
        
    -- Some executors use getconnections as a stand-in for firesignal, but they forget to pass args
    assert(typeof(result) == "boolean", "firesignal failed to pass arguments")
    -- Firesignal should yield until the signal has been fired
    assert(result, "firesignal failed to fire the signal")
end)

test("fireclickdetector", {}, function()
    local done = false
    local detector = Instance.new("ClickDetector")

    detector.MouseClick:Connect(function()
        done = true
    end)
    fireclickdetector(detector, 1, "MouseClick")
    assert(done, "fireclickdetector did not fire the ClickDetector")
    assert(pcall(fireclickdetector, detector, nil, "MouseClick"),
        "fireclickdetector should not error when given nil as a distance parameter")
end, fireclickdetector)

test("firetouchinterest", {}, function()
    local done, number = false, 0
    local part = Instance.new("Part")
    part.Parent = game:GetService("Workspace")
    part.Touched:Connect(function()
        done = true
        number = number + 1
    end)

    firetouchinterest(game:GetService("Workspace").Part, game:GetService("Players").LocalPlayer.Character.PrimaryPart, 0)
    task.wait()
    firetouchinterest(game:GetService("Workspace").Part, game:GetService("Players").LocalPlayer.Character.PrimaryPart, 1)
    assert(done, "firetouchinterest did not activate the TouchTransmitter callback")
    assert(number == 1, "firetouchinterest should only activate the TouchTransmitter callback once")
    game:GetService("Workspace").Part:Destroy()
end, firetouchinterest)

test("fireproximityprompt", {}, function()
    
end, fireproximityprompt)

test("getcallbackvalue", {}, function()
    local bindable = Instance.new("BindableFunction")
    local function test()
    end
    bindable.OnInvoke = test
    assert(getcallbackvalue(bindable, "OnInvoke") == test, "getcallbackvalue did not return the correct value")
end, getcallbackvalue)

test("getconnections", {}, function()
    local types = {
        Enabled = "boolean",
        ForeignState = "boolean",
        LuaConnection = "boolean",
        Function = "function",
        Thread = "thread",
        Fire = "function",
        Defer = "function",
        Disconnect = "function",
        Disable = "function",
        Enable = "function",
    }
    local bindable = Instance.new("BindableEvent")
    bindable.Event:Connect(function() end)
    local connection = getconnections(bindable.Event)[1]
    for k, v in pairs(types) do
        assert(connection[k] ~= nil, "getconnections did not return a table with a '" .. k .. "' field")
        assert(type(connection[k]) == v,
            "getconnections did not return a table with " .. k .. " as a " .. v .. " (got " .. type(connection[k]) .. ")")
    end
end, getconnections)

test("getcustomasset", {}, function()
    writefile(".tests/getcustomasset.txt", "success")
    local contentId = getcustomasset(".tests/getcustomasset.txt")
    assert(type(contentId) == "string", "getcustomasset did not return a string")
    assert(#contentId > 0, "getcustomasset returned an empty string")
    assert(string.match(contentId, "rbxasset://") == "rbxasset://", "getcustomasset did not return an rbxasset url")
    -- no one uses this anymore 😭
end)

test("gethiddenproperty", {}, function()
    local fire = Instance.new("Fire")
    local property, isHidden = gethiddenproperty(fire, "size_xml")
    assert(property == 5, "gethiddenproperty did not return the correct value")
    assert(isHidden == true, "gethiddenproperty did not return whether the property was hidden")
end, gethiddenproperty)

test("sethiddenproperty", {}, function()
    local fire = Instance.new("Fire")
    local hidden = sethiddenproperty(fire, "size_xml", 10)
    assert(hidden, "sethiddenproperty did not return true for the hidden property")
    assert(gethiddenproperty(fire, "size_xml") == 10, "sethiddenproperty did not set the hidden property")
end, sethiddenproperty)

test("gethui", {}, function()
    assert(typeof(gethui()) == "Instance", "gethui did not return an Instance")
    assert(gethui() == game:GetService("CoreGui") or gethui() == game:GetService("Players").LocalPlayer.PlayerGui,
        "gethui did not return the CoreGui Instance or the PlayerGui Instance")
end, gethui)

test("getinstances", {}, function()
    assert(getinstances()[1]:IsA("Instance"), "The first value of getinstances is not an Instance")
end, getinstances)

test("getnilinstances", {}, function()
    assert(getnilinstances()[1]:IsA("Instance"), "The first value of getnilinstances is not an Instance")
    assert(getnilinstances()[1].Parent == nil, "The first value of getnilinstances is not parented to nil")
end, getnilinstances)

test("isscriptable", {}, function()
    local fire = Instance.new("Fire")
    assert(isscriptable(fire, "size_xml") == false,
        "isscriptable did not return false for a non-scriptable property (size_xml)")
    assert(isscriptable(fire, "Size") == true, "isscriptable did not return true for a scriptable property (Size)")
end, isscriptable)

test("setscriptable", {}, function()
    local fire = Instance.new("Fire")
    local wasScriptable = setscriptable(fire, "size_xml", true)
    assert(wasScriptable == false, "setscriptable did not return false for a non-scriptable property (size_xml)")
    assert(isscriptable(fire, "size_xml") == true, "setscriptable did not set the scriptable property")
    fire = Instance.new("Fire")
    assert(isscriptable(fire, "size_xml") == false, "setscriptable persists between unique instances")
end, setscriptable)

-- Metatable

test("getrawmetatable", {}, function()
    local metatable = { __metatable = "Locked!" }
    local object = setmetatable({}, metatable)
    assert(getrawmetatable(object) == metatable, "getrawmetatable did not return the metatable")
end, getrawmetatable)

test("hookmetamethod", {}, function()
    local object = setmetatable({}, { __index = newcclosure(function() return false end), __metatable = "Locked!" })
    local ref = hookmetamethod(object, "__index", function() return true end)
    assert(object.test == true, "Failed to hook a metamethod and change the return value")
    assert(ref() == false, "hookmetamethod did not return the original function")
end, hookmetamethod)

test("isreadonly", {}, function()
    local object = {}
    table.freeze(object)
    assert(isreadonly(object), "isreadonly did not return true for a read-only table")
end, isreadonly)

test("setrawmetatable", {}, function()
    local object = setmetatable({}, { __index = function() return false end, __metatable = "Locked!" })
    local objectReturned = setrawmetatable(object, { __index = function() return true end })
    assert(object, "setrawmetatable did not return the original object")
    assert(object.test == true, "setrawmetatable failed to change the metatable")
    if objectReturned then
        return objectReturned == object and "setrawmetatable returned the original object" or
            "setrawmetatable did not return the original object"
    end
end, setrawmetatable)

test("setreadonly", {}, function()
    local object = { success = false }
    table.freeze(object)
    setreadonly(object, false)
    object.success = true
    assert(object.success, "setreadonly did not allow the table to be modified")
end, setreadonly)

-- Miscellaneous

test("printidentity", {}, function()
    -- thanks vxsty
    local conn
    local Identity, Identity2, Check2
    conn = game:GetService("LogService").MessageOut:Connect(function(message, messageType)
        if message:find("Current identity is") then
            Identity = message
        end
        if Check2 then
            Identity2 = message
            conn:Disconnect()
        end
    end)
    printidentity()
    repeat task.wait() until Identity
    Identity1 = tonumber(Identity:gsub('Current identity is', ''):match("%d+"))
    if Identity1 > 9 then
        assert(false, "PrintIdentity validation failed: Identity cannot be over 9")
        return
    end
    local Source1 = debug.info(printidentity, 's')

    local setfenvsuccess, e = pcall(function()
        setfenv(printidentity, {})
    end)

    local success
    local sti = set_thread_identity or setthreadidentity

    if sti then
        setthreadidentity(3)
        Check2 = true
        printidentity()
        repeat task.wait() until Identity2
        success = Identity2 ~= 'Current identity is 3'
    end

    local Tests = {
        [1] = Source1 ~= '[C]',
        [2] = setfenvsuccess,
        [3] = success,
        [4] = iscclosure and not iscclosure(printidentity)
    }

    local TestResults = {
        [1] = "PrintIdentity hardcoded to return 8 always",
        [2] = 'PrintIdentity hardcoded to return 8 always with newcclosure.',
        [3] = 'PrintIdentity not same as getthreadidentity after setthreadidentity',
        [4] = 'PrintIdentity hardcoded to return 8 always'
    }

    for index, val in next, Tests do
        if val then
            assert(false, "PrintIdentity validation failed: " .. TestResults[index])
        end
    end
end, printidentity)

test("identifyexecutor", { "getexecutorname" }, function()
    local name, version = identifyexecutor()
    assert(type(name) == "string", "identifyexecutor did not return a string for the name")
    return type(version) == "string" and "identifyexecutor returns version as a string" or
        "identifyexecutor does not return version"
end, identifyexecutor)

test("lz4compress", {}, function()
    local raw = "Hello, world!"
    local compressed = lz4compress(raw)
    assert(type(compressed) == "string", "Compression did not return a string")
    assert(lz4decompress(compressed, #raw) == raw, "Decompression did not return the original string")
end, lz4compress)

test("lz4decompress", {}, function()
    local raw = "Hello, world!"
    local compressed = lz4compress(raw)
    assert(type(compressed) == "string", "Compression did not return a string")
    assert(lz4decompress(compressed, #raw) == raw, "Decompression did not return the original string")
end, lz4decompress)

test("messagebox", {}, nil, messagebox)

test("queue_on_teleport", { "queueonteleport" }, nil, queue_on_teleport)

test("script") -- controlled in test function as script isn't a function its a global var

test("secure_call", {}, function()
    assert(not pcall(secure_call, "hello = nil"), "secure_call should only accept a function")
    assert(secure_call ~= loadstring, "secure_call should not be the same function as loadstring")
    assert(typeof(secure_call("hello = nil")) ~= "function",
        "secure_call should not return a function; instead execute directly")
end, secure_call)

test("request", { "http.request", "http_request" }, function()
    local response = request({
        Url = "https://httpbin.org/user-agent",
        Method = "GET",
    })
    assert(type(response) == "table", "request response must be a table")
    assert(response.StatusCode == 200, "request did not return a 200 status code")
    local data = game:GetService("HttpService"):JSONDecode(response.Body)
    assert(type(data) == "table" and type(data["user-agent"]) == "string",
        "request did not return a table with a user-agent key")
    assert(data["roblox-game-id"] == tostring(game.JobId), "request did not return the correct game id")
    assert(data["roblox-session-id"] == tostring(game.JobId), "request did not return the correct session id")
    return "User-Agent: " .. data["user-agent"]
end, request)

test("gethwid", { "get_hwid" }, function()
	assert(typeof(gethwid()) == "string", "gethwid does not return a valid string")
end, gethwid)

test("setclipboard", { "setrbxclipboard", "toclipboard" }, function()
    setclipboard("UNC v2 clipboard test")
end, setclipboard)

test("getclipboard", { "getrbxclipboard" }, function()
    assert(getclipboard() == "UNC v2 clipboard test", "getclipboard did not return the correct value")
end, getclipboard)

test("setfpscap", {}, function()
    task.spawn(function()
        local renderStepped = game:GetService("RunService").RenderStepped
        local function step()
            renderStepped:Wait()
            local sum = 0
            for _ = 1, 5 do
                sum = sum + 1 / renderStepped:Wait()
            end
            return math.round(sum / 5)
        end
        setfpscap(60)
        local step60 = step()
        setfpscap(0)
        local step0 = step()
        return step60 .. "fps @60 • " .. step0 .. "fps @0"
    end)
end, setfpscap)

-- Scripts

test("getgc", { "getgarbagecollector" }, function()
    local gc = getgc()
    assert(type(gc) == "table", "getgc did not return a table")
    assert(#gc ~= 0, "getgc did not return a table with any values")
    assert(getgc ~= debug.getregistry, "debug.getgc should not be the same as getregistry")
end, getgc)

test("getgenv", {}, function()
    getgenv().__TEST_GLOBAL = true
    assert(__TEST_GLOBAL, "Failed to set a global variable")
    getgenv().__TEST_GLOBAL = nil
end, getgenv)

test("getallthreads", { "getthreads" }, function()
    assert(typeof(getallthreads()) == "table", "getallthreads did not return a table")
    assert(#getallthreads() ~= 0, "getallthreads returned a empty table")
    assert(typeof(getallthreads()[1]) == "thread", "Returned table contains non-thread type")
end, getallthreads)

test("getloadedmodules", {}, function()
    local modules = getloadedmodules()
    assert(type(modules) == "table", "getloadedmodules did not return a table")
    assert(#modules > 0, "getloadedmodules did not return a table with any values")
    assert(typeof(modules[1]) == "Instance", "The first value of getloadedmodules is not an Instance")
    assert(modules[1]:IsA("ModuleScript"), "The first value of getloadedmodules is not a ModuleScript")
end, getloadedmodules)

test("getrenv", {}, function()
    assert(_G ~= getrenv()._G, "The variable _G in the executor is identical to _G in the game")
end, getrenv)

test("getrunningscripts", {}, function()
    local scripts = getrunningscripts()
    assert(type(scripts) == "table", "getrunningscripts did not return a table")
    assert(#scripts > 0, "getrunningscripts did not return a table with any values")
    assert(typeof(scripts[1]) == "Instance", "The first value of getrunningscripts is not an Instance")
    assert(scripts[1]:IsA("ModuleScript") or scripts[1]:IsA("LocalScript"),
        "The first value of getrunningscripts is not a ModuleScript or LocalScript")
end, getrunningscripts)

test("getscriptbytecode", { "dumpstring" }, function()
    local animate = game:GetService("Players").LocalPlayer.Character.Animate
    local bytecode = getscriptbytecode(animate)
    assert(type(bytecode) == "string",
        "getscriptbytecode did not return a string for Character.Animate (a " .. animate.ClassName .. ")")
end, getscriptbytecode)

test("getscripthash", {}, function()
    local animate = game:GetService("Players").LocalPlayer.Character.Animate:Clone()
    local hash = getscripthash(animate)
    local source = animate.Source
    animate.Source = "print('Hello, world!')"
    task.defer(function()
        animate.Source = source
    end)
    local newHash = getscripthash(animate)
    assert(hash ~= newHash, "getscripthash did not return a different hash for a modified script")
    assert(newHash == getscripthash(animate),
        "getscripthash did not return the same hash for a script with the same source")
    assert(newHash ~= animate:GetHash(), "getscripthash should not be the same as :GetHash()")
end, getscripthash)

test("getscripts", {}, function()
    local scripts = getscripts()
    assert(type(scripts) == "table", "getscripts did not return a table")
    assert(#scripts > 0, "getscripts did not return a table with any values")
    assert(typeof(scripts[1]) == "Instance", "The first value of getscripts is not an Instance")
    assert(scripts[1]:IsA("ModuleScript") or scripts[1]:IsA("LocalScript"),
        "The first value of getscripts is not a ModuleScript or LocalScript")
end, getscripts)

test("getsenv", {}, function()
    local animate = game:GetService("Players").LocalPlayer.Character.Animate
    local env = getsenv(animate)
    assert(type(env) == "table", "getsenv did not return a table for Character.Animate (a " .. animate.ClassName .. ")")
    assert(env.script == animate, "The script global is not identical to Character.Animate")
end, getsenv)

test("getthreadidentity", { "getidentity", "getthreadcontext", "get_thread_identity" }, function()
    assert(type(getthreadidentity()) == "number", "getthreadidentity did not return a number")
end, getthreadidentity)

test("setthreadidentity", { "setidentity", "setthreadcontext", "set_thread_identity" }, function()
    setthreadidentity(3)
    assert(getthreadidentity() == 3, "setthreadidentity did not set the thread identity")
end, setthreadidentity)

-- Drawing

test("Drawing", {})

test("Drawing.new", {}, function()
    local drawing = Drawing.new("Square")
    drawing.Visible = false
    local canDestroy = pcall(function()
        drawing:Destroy()
    end)
    assert(canDestroy, "Drawing:Destroy() should not throw an error")
end, Drawing.new)

test("Drawing.Fonts", {}, function()
    -- honestly is this even necessary
    assert(Drawing.Fonts.UI == 0, "Drawing.Fonts did not return the correct id for UI")
    assert(Drawing.Fonts.System == 1, "Drawing.Fonts did not return the correct id for System")
    assert(Drawing.Fonts.Plex == 2, "Drawing.Fonts did not return the correct id for Plex")
    assert(Drawing.Fonts.Monospace == 3, "Drawing.Fonts did not return the correct id for Monospace")
end) -- table so no closure check

test("isrenderobj", {}, function()
    local drawing = Drawing.new("Image")
    drawing.Visible = true
    assert(isrenderobj(drawing) == true, "isrenderobj did not return true for an Image")
    assert(isrenderobj(newproxy()) == false, "isrenderobj did not return false for a blank table")
end, isrenderobj)

test("getrenderproperty", {}, function()
    local drawing = Drawing.new("Image")
    drawing.Visible = true
    assert(type(getrenderproperty(drawing, "Visible")) == "boolean", "Did not return a boolean value for Image.Visible")
    local success, result = pcall(function()
        return getrenderproperty(drawing, "Color")
    end)
    if not success or not result then
        return "Image.Color is not supported"
    end
end, getrenderproperty)

test("setrenderproperty", {}, function()
    local drawing = Drawing.new("Square")
    drawing.Visible = true
    setrenderproperty(drawing, "Visible", false)
    assert(drawing.Visible == false, "setrenderproperty did not set the value for Square.Visible")
end, setrenderproperty)

test("cleardrawcache", {}, function()
    local testdraw = Drawing.new("Circle")
    testdraw.Visible = false
    cleardrawcache()
    assert(testdraw == nil, "cleardrawcache did not clear the Drawing cache")
end, cleardrawcache)

-- WebSocket

test("WebSocket", {})

test("WebSocket.connect", {}, function()
    local types = {
        Send = "function",
        Close = "function",
        OnMessage = { "table", "userdata" },
        OnClose = { "table", "userdata" },
    }
    getgenv().wsc = WebSocket.connect("ws://echo.websocket.events")
    assert(type(wsc) == "table" or type(wsc) == "userdata", "WebSocket.connect did not return a table or userdata")
    for k, v in pairs(types) do
        if type(v) == "table" then
            assert(table.find(v, type(wsc[k])),
                "WebSocket.connect did not return a " ..
                table.concat(v, ", ") .. " for " .. k .. " (a " .. type(wsc[k]) .. ")")
        else
            assert(type(wsc[k]) == v,
                "WebSocket.connect did not return a " .. v .. " for " .. k .. " (a " .. type(wsc[k]) .. ")")
        end
    end
end, WebSocket.connect)

test("WebSocket.disconnect", {}, function()
    WebSocket.disconnect(wsc)
    assert(not pcall(function() WebSocket:Close(wsc) end),
        "WebSocket:Close() should throw a error if already disconnected")
end, WebSocket.disconnect)
getgenv().wsc = nil
