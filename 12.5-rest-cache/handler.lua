local _plugin = require "kong.plugins.base_plugin":extend()
local _redis = require 'kong.plugins.rest-cache.redis'
local _encoder = require 'kong.plugins.rest-cache.encoder'
--�������
local HEADER_Transfer_Encoding = "transfer-encoding"
--��������json
local HEADER_Application_Json = "application/json"
--����Ϊ��λ����Ӧͷ��������Ӧ����ʱ��
local HEADER_Accel_Expires = "X-Accel-Expires"
--��������
local HEADER_Content_Type = "Content-Type"
--REST Cache���б�ʶ
local HEADER_X_Rest_Cache = "x-rest-cache"
--����Headerͷ
local HEADER_Connection = "connection"

function _plugin:new()
    _plugin.super.new(self, "rest-cache")
end
--��������key
local function generate_cache_key()
    local cache_key =
    kong.request.get_host() .. ':' ..
    kong.request.get_method() .. ':' ..
    kong.request.get_path_with_query()
    return string.lower(cache_key)
end
--�����ݽ��б������л����첽д��Զ��redis
local function async_write_cache(config, cache_key, body, headers, status)
    ngx.timer.at(0, function(premature)
        local redis = _redis:new()
        redis:init(config)
        local cache_value = _encoder.encode(status, body, headers)
        redis:set(cache_key, cache_value, config.cache_ttl)
    end)
end

function _plugin:access(config)
    _plugin.super.access(self)
    
    local method = kong.request.get_method()
    if method ~= "GET" then
        return
    end
    
    local redis = _redis:new()
    redis:init(config)
    --���ɻ���key
    local cache_key = generate_cache_key()
    --��ѯredis
    local cached_value, err = redis:get(cache_key)
    if cached_value and cached_value ~= ngx.null then
        --�����е����ݽ��н��뷴���л�
        local response = _encoder.decode(cached_value)
        kong.response.set_header("X-REST-Cache", "Hit")
        if response.headers then
            for header, value in pairs(response.headers) do
                kong.response.set_header(header, value)
            end
        end
        kong.response.exit(200, response.content)
        return
    else
        kong.response.set_header("X-REST-Cache", "Miss")
        ngx.ctx.response_cache = {cache_key = cache_key}
    end
    
end

function _plugin:body_filter(config)
    _plugin.super.body_filter(self)
    
    local ctx = ngx.ctx.response_cache
    if not ctx then
        return
    end
    --������η�����ָ���˷��ع���ʱ��(��)�������������еı�׼�Ĺ���ʱ��
    local cache_ttl = kong.service.response.get_header(HEADER_Accel_Expires)
    if cache_ttl then
        config.cache_ttl = cache_ttl
    end
    
    local chunk = ngx.arg[1]
    local eof = ngx.arg[2]
    --����������ݽϴ�ֱ�����յ���������
    local res_body = ctx and ctx.res_body or ""
    res_body = res_body .. (chunk or "")
    ctx.res_body = res_body
    
    local status = kong.response.get_status()
    local content_type = kong.response.get_header(HEADER_Content_Type)
    --�����ص������첽д��redis���������뷵��״̬Ϊ200��Ϊjson��ʽ
    if eof and status == 200 and content_type and content_type == HEADER_Application_Json then
        local headers = kong.response.get_headers()
        headers[HEADER_Connection] = nil
        headers[HEADER_X_Rest_Cache] = nil
        headers[HEADER_Transfer_Encoding] = nil
        async_write_cache(config, ctx.cache_key, ctx.res_body, headers, status)
    end
    
end

_plugin.PRIORITY = 1001
_plugin.VERSION = '1.0.0'
return _plugin
