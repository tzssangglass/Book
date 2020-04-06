--��ǰ���ݰ汾
local data_version = 0
--�û������ٶȵ����ݻ���ʵ�
local user_limit_data_dict = {}
local plugin = require("kong.plugins.base_plugin"):extend()

function plugin:new()
    plugin.super.new(self, "download-rate-limiting")
end
--�ԡ�:���ţ������ݽ��в�֣�����key/value
local function iter(config_array)
    --ͬ��
    ����
end
--��ʹ������
local function init_data(config_array)
    for _, name, value in iter(config_array) do
        user_limit_data_dict[name] = value
    end
end

function plugin:access(conf)
    plugin.super.access(self)
    --�жϲ�����ݰ汾�Ƿ����仯����仯��Ҫ���³�ʹ��
    if(conf.data_version > data_version) then
        user_limit_data_dict = {}
        init_data(conf.user_limit_values)
        data_version = conf.data_version
    end
    --��ȡָ����header�������ݣ�����ȡ��user id
    local user_id = kong.request.get_header(conf.user_id_header_name)
    --�ж��Ƿ�ȡ��user id���Ƿ������������
    if user_id and user_limit_data_dict[user_id] then
        --�����������У������������������ٶ�
        ngx.var.limit_rate = user_limit_data_dict[user_id]
    else
        --�������������У�ʹ��Ĭ������ֵ���������ٶ�
        ngx.var.limit_rate = conf.default_rate_limiting
    end
    
end
--������ȼ�
plugin.PRIORITY = 10

return plugin
