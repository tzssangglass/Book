local policies = require "kong.plugins.rate-limiting.policies"
local BasePlugin = require "kong.plugins.base_plugin"
local timestamp = require "kong.tools.timestamp"
local lrucache = require "resty.lrucache"
local pl_stringx = require "pl.stringx"
local lower = string.lower
local fmt = string.format
local tostring = tostring
local sort = table.sort
local ngx_log = ngx.log
local pairs = pairs
local cache
--所使用的速率限制ID
local RATELIMIT_ID = "X-RateLimit-Id"
--是打开速率日志调试
local RATELIMIT_DEBUG = "X-RateLimit-Match"
--速率限制数量
local RATELIMIT_LIMIT = "X-RateLimit-Limit"
--速率限制剩余数量
local RATELIMIT_REMAINING = "X-RateLimit-Remaining"
--速率限制超出的提示
local RATELIMIT_EXCEEDED = "Rate limit exceeded"
--限制的方法请求
local METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}
--数据是否已经初使化
local _inited = false
--当前数据版本
local _data_version = 0
--企业请求路径每秒速率限制次数
local _enterprise_paths_limiting_seconds_count = 0
--企业请求路径每秒速率限制词典
local _enterprise_paths_limiting_seconds_sorted = {}

local plugin = BasePlugin:extend()

--[[
Item size:1024 bytes = 1K
Max memory limit: 10 MiBs
2^20=1048576 bytes=1M
LRU size must be: (10 * 2^20) / 1024 = 10240
]]
--设置lrucache缓存大小
local MATCH_SIZE = 102400

plugin.PRIORITY = 901
plugin.VERSION = "0.1.0"

function plugin:new()
    plugin.super.new(self, "rate-limiting-plus")
    --初使化lrucache缓存
    cache = lrucache.new(MATCH_SIZE)
end
--以“:”号，将数据进行拆分，返回key/value
local function iter(config_array, match_string)
    --同上
    ……
end
--写入debug调试信息日志到response头
local function output_debug(message, conf)
    if conf.debug_mode == true and message then
        kong.response.set_header(RATELIMIT_DEBUG, message)
    end
end
--限制速率数据发生变化，重新解析
local function re_parse(limit_data)
    --请求方法为*设置缓存速率值
    if limit_data.key == "*" then
        _enterprise_paths_limiting_seconds_sorted[_enterprise_paths_limiting_seconds_count + 1] = limit_data
        return
    end
    
    --请求方法设置缓存速率值
    for i, v in ipairs(METHODS) do
        limit_data.method = lower(v)
        _enterprise_paths_limiting_seconds_sorted[_enterprise_paths_limiting_seconds_count + 1] = limit_data
    end
    
end

--为本地缓存，初使化需要解析的数据
local function init_parse_data(conf)
    
    local counting = 1
    for index, key, value in iter(conf.level_1_limiting_second, "^([^:]+):*(.-)$") do
        for index1, key1, value1 in iter({key}, "^([^|]+)|*(.-)$") do
            for index2, key2, value2 in iter({value1}, "^([^|]+)|*(.-)$") do
                re_parse({
                    key = lower(key),
                    enterprise = key1,
                    method = lower(key2),
                    path = lower(value2),
                limit = tonumber(value)})
            end
        end
    end
    
    sort(_enterprise_paths_limiting_seconds_sorted, function(v1, v2) return #v1.key > #v2.key end)
    cache = lrucache.new(MATCH_SIZE)
    _data_version = conf.version;
    _inited = true
end

--找到需要计数的identifier
local function find_identifier(enterprise_id, host, path, method, client_ip, conf)
    
    local cache_key = fmt("%s:%s:%s:%s:%s", enterprise_id, host, path, method, client_ip)
    --首先从缓存中查找，如果查找到立即返回
    do
        local match_identifier = cache:get(cache_key)
        if match_identifier then
            output_debug(match_identifier.name, conf)
            return match_identifier
        end
    end
    
    --从需要限流的所有路径中查找是否匹配
    local key = enterprise_id .. "|" .. method .. "|" .. path
    for _, limiting in pairs(_enterprise_paths_limiting_seconds_sorted) do
        local from, to = string.find(key, limiting.key, nil, true)
        if from ~= nil then
            local identifier = {
                name = string.format("%s_%s_%s_%s_%s_%s",
                    limiting.enterprise, host,
                    limiting.path, method,
                client_ip, "spec"),
            limit = limiting.limit, id = 1}
            
            cache:set(cache_key, identifier)
            return identifier
        end
    end
end

--取得identifiers的限制速率的基础数据
local function get_identifiers_limits(enterprise_id, conf)
    
    local identifiers = {}
    local client_ip = kong.client.get_forwarded_ip()
    local method = lower(kong.request.get_method())
    local host = lower(kong.request.get_host())
    local path = lower(kong.request.get_path())
    --严格匹配
    identifiers[1] = find_identifier_strict(enterprise_id, path, method, client_ip)
    --分级匹配
    identifiers[2] =
    {name = string.format("%s_%s_%s_%s_%s", enterprise_id, host, path, method, client_ip), limit = conf.level_2_limiting_second, id = 2}
    identifiers[3] = {name =
    string.format("%s_%s_%s", enterprise_id, host, client_ip), limit = conf.level_3_limiting_second, id = 3}
    identifiers[4] =
    {name = string.format("%s_%s", host, client_ip), limit = conf.level_4_limiting_second, id = 4}
    
    return identifiers
    
end

--取得当前限制的每秒使用量
local function get_usage(conf, identifiers, current_timestamp)
    
    local name = "second"
    local usage = {}
    local stop
    for _, identifier in pairs(identifiers) do
        
        if identifier ~= nil then
            local current_usage, err = policies[conf.policy].usage(conf, identifier.name, current_timestamp, name)
            if err then
                return nil, nil, err
            end
            
            local remaining = identifier.limit - current_usage
            
            -- Recording usage
            usage[name] = {
                id = identifier.id,
                limit = identifier.limit,
                remaining = remaining
            }
            
            if remaining <= 0 then
                stop = name
                return usage, stop
            end
        end
        
    end
    
    return usage, stop
end

function plugin:access(conf)
    plugin.super.access(self)
    --首次初使化缓存数据或版本发生变化重新初使化缓存数据
    if not _inited or conf.version > _data_version then
        init_parse_data(conf)
    end
    
    local policy = conf.policy
    local fault_tolerant = conf.fault_tolerant
    local current_timestamp = timestamp.get_utc()
    --从请求header中读取企业ID
    local enterprise_id = kong.request.get_header(conf.header_name)
    --如果未读取到企业ID
    if enterprise_id == nil then
        return kong.response.exit(400, "enterprise id is empty")
        --如果读取的企业ID不是5位或不是数值类型
    elseif #enterprise_id ~= 5 or tonumber(enterprise_id) == nil then
        return kong.response.exit(400, "enterprise id error")
    end
    --取得identifiers的限制速率的基础数据
    local identifiers = get_identifiers_limits(enterprise_id, conf)
    --取得当前使用量
    local usage, stop, err = get_usage(conf, identifiers, current_timestamp)
    if err then
        if fault_tolerant then
            ngx_log(ngx.ERR, "failed to get usage: ", tostring(err))
        else
            return kong.response.exit(500, err)
        end
    end
    
    if usage then
        if not conf.hide_client_headers then
            for k, v in pairs(usage) do
                --设置客户端返回的header信息
                ngx.header[RATELIMIT_ID .. "-" .. k] = v.id
                ngx.header[RATELIMIT_LIMIT .. "-" .. k] = v.limit
                ngx.header[RATELIMIT_REMAINING .. "-" .. k] = math.max(0, (stop == nil or stop == k) and v.remaining - 1 or v.remaining)
            end
        end
        --如果达到速率所限制的使用量，返回超出限制信息
        if stop then
            kong.log.warn(RATELIMIT_EXCEEDED, kong.request.get_host(), kong.request.get_path())
            return kong.response.exit(429, RATELIMIT_EXCEEDED)
        end
    end
    --未超出使用量，增加请求统计信息
    for _, identifier in pairs(identifiers) do
        policies[policy].increment(conf, {second = identifier.limit}, identifier.name, current_timestamp, 1)
    end
    
end

return plugin
