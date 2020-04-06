local plugin = require("kong.plugins.base_plugin"):extend()

function plugin:new()
    plugin.super.new(self, "bridg-data-center")
end

function plugin:access(plugin_conf)
    plugin.super.access(self)
    --ȡ�õ�ǰʹ�õ����η���������
    local upstream_name = kong.router.get_service().host
    --�жϵ�ǰ���ؾ��������Ƿ��ǽ���״̬
    local health = kong.upstream.get_balancer_health(upstream_name).health
    --�����ǰ���ؾ�����Ϊ��������ת������һ����������
    if(health and health ~= "HEALTHY") then
        local dc_upstream_name = upstream_name .. "_" .. plugin_conf.failover_data_center
        kong.service.set_upstream(dc_upstream_name)
    end
    
end

plugin.PRIORITY = 1000

return plugin
