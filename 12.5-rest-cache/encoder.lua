local cjson_decode = require("cjson").decode
local cjson_encode = require("cjson").encode

local _M = {}
--�����ݽ���json���룬���ض���
local function json_decode(json)
    if json then
        local status, res = pcall(cjson_decode, json)
        if status then
            return res
        end
    end
end
--�����ݽ��б��뷵���ַ���
local function json_encode(table)
    if table then
        local status, res = pcall(cjson_encode, table)
        if status then
            return res
        end
    end
end
--�������л�
function _M.encode(status, content, headers)
    return json_encode({
        status = status,
        content = content,
        headers = headers
    })
end
--���뷴���л�
function _M.decode(str)
    return json_decode(str)
end

return _M
