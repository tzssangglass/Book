local plugin = require("kong.plugins.base_plugin"):extend()
local pl_stringx = require "pl.stringx"
local http = require "resty.http"
local md5 = ngx.md5

function plugin:new()
    plugin.super.new(self, "static-file-concat")
end
--��Զ�̷�������ȡ������̬�ļ���Դ����
local function query_from_server(path, conf)
    local httpc = http:new()
    httpc:connect(conf.static_file_host, conf.static_file_port)
    httpc:set_timeout(conf.connect_timeout)
    local res, err = httpc:request {
        path = "/" .. path,
        method = "GET"
    }
    if err or res.status ~= 200 then
        kong.log.err("request error: ", res.status, path)
        return "", err
    end
    
    local data = res:read_body()
    --����keepalive������
    local ok, err = httpc:set_keepalive(conf.connect_pool_idle_timeout, conf.connect_pool_size)
    if not ok then
        kong.log.err("could not keepalive connection: ", err)
        return "", err
    end
    return data, nil
end
--�������̬��Դ�ļ����ݺϲ�
local function generate_content(file_parts, conf)
    local content = ""
    file_parts[1] = pl_stringx.lstrip(file_parts[1], "?")
    for _, file in ipairs(file_parts) do
        local file_data, err = query_from_server(file, conf)
        if err then
            kong.log.err("internal-error: ", err)
            return nil, err, 10
        end
        content = content.. conf.concat_delimiter .. file_data
    end
    --�жϺϲ������ݴ�С�Ƿ񳬹�����
    if #content > conf.concat_max_files_size then
        kong.log.err("[concat_max_files_size] exceeded limit: ", conf.concat_max_files_size)
        return nil, "File size exceeded limit:" .. conf.concat_max_files_size, 10
    end
    
    return content, nil, conf.key_ttl
end

function plugin:access(conf)
    plugin.super.access(self)
    local query = kong.request.get_raw_query()
    local is_double_question = pl_stringx.startswith(query, '?')
    
    if not is_double_question then
        return
    end
    --��������ļ����в�֣��ж��Ƿ񳬹�����
    local file_parts = pl_stringx.split(query, ';')
    if file_parts and #file_parts > conf.concat_max_files_number then
        kong.log.err("[concat_max_files_number] exceeded : ", conf.concat_max_files_number)
        return kong.response.exit(400, "File number exceeded limit")
    end
    --������Ķ����̬��Դ�ļ��б���й�ϣ
    local uri_md5 = md5(query)
    local cache_key = "concat_" .. uri_md5
    print("cache_key:" .. cache_key)
    --�ӻ����в����Ƿ��Ѿ��Ǻϲ�������ݣ�����ֱ�ӷ��أ���֮���ɺϲ��������
    -- kong.cache����lua-resty-mlcache�༶���桢�����ƣ�ȷ��ԭ�ӻص�
    local content, err = kong.cache:get(cache_key, {ttl = 0}, generate_content, file_parts, conf)
    
    if err then
        kong.log.err("internal-error: ", err)
        return kong.response.exit(500, "Internal error")
    end
    
    if content == nil then
        kong.log.err("internal-error: static content is null")
        return kong.response.exit(500, "Cache error")
    end
    
    return kong.response.exit(200, content)
    
end

plugin.PRIORITY = 1000
return plugin
