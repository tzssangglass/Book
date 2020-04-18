local LIMITING_LEVEL = {
    "10000|GET|/user:10",
    "10001|GET|/user:20"
}

return {
    no_consumer = true,
    fields = {
        
        version = {type = "number", default = 1},
        header_name = {type = "string", default = "enterprise_id"},
        
        level_4_limiting_second = {type = "number", default = 4}, --Level-4
        level_3_limiting_second = {type = "number", default = 3}, --Level-3
        level_2_limiting_second = {type = "number", default = 2}, --Level-2
        level_1_limiting_second = {type = "array", default = LIMITING_LEVEL, }, --Level-1
        
        policy = {type = "string", enum = {"local", "cluster", "redis"}, default = "local"},
        fault_tolerant = {type = "boolean", default = true},
        redis_host = {type = "string"},
        redis_port = {type = "number", default = 6379},
        redis_password = {type = "string"},
        redis_timeout = {type = "number", default = 2000},
        redis_database = {type = "number", default = 0},
        hide_client_headers = {type = "boolean", default = false},
        
    }}
    
