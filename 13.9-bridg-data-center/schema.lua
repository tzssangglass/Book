return {
  no_consumer = true,
  fields = {
    --���η���������
    upstream_service_name = { required = true, type = "string" },
    --ʧЧ��Ԯ�����η������������ģ��������Ϻ�
    failover_data_center = { type = "string", enum = {"beijing", "shanghai"}, default = "beijing" },
  }
}
