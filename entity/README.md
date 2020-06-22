# 采集到的接口数据入数据库

# tab_capture

字段信息

```
1、id
2、msg_type 消息类型 请求还是响应
3、msg_uuid 消息唯一编码
4、msg_time 消息采集时间
5、msg_hex  消息二进制
6、msg_dumphex 消息可以看的二进制
7、msg_srcip 消息发起的原始IP地址
8、msg_srcport 消息的原始端口
9、msg_dstip 消息的目的IP
10、msg_dstport 消息的目的端口
11、sys_id 采集系统的标识码
12、sys_subid 子系统标识码
13、protocol_type  通讯协议类型  tcp/udp/http/dubbo 等
14、parse_fun  报文解析组件名称默认DefaultParse
15、create_time 插入时间

```





```
CREATE TABLE `tab_capture` (
	`mid` INT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
	`msg_type` VARCHAR(128) NULL DEFAULT NULL COMMENT '消息类型',
	`msg_uuid` VARCHAR(128) NULL DEFAULT NULL COMMENT 'uuid消息',
	`msg_time` int  COMMENT '采集时间',
	`msg_cost` int  COMMENT '响应耗时',
	`msg_len` int  COMMENT '消息长度',
	`msg_hex` TEXT NULL COMMENT '采集消息内容',
	`msg_dumphex` TEXT NULL COMMENT '采集消息内容可视化',
	`msg_srcip` VARCHAR(128) NULL DEFAULT NULL COMMENT '原始IP',
	`msg_srcport` VARCHAR(128) NULL DEFAULT NULL COMMENT '请求端口',
	`msg_dstip` VARCHAR(128) NULL DEFAULT NULL COMMENT '目的IP',
	`msg_dstport` VARCHAR(128) NULL DEFAULT NULL COMMENT '目的端口',
	`sys_id` VARCHAR(128) NULL DEFAULT NULL COMMENT '系统ID',
	`sys_subid` VARCHAR(128) NULL DEFAULT NULL COMMENT '子系统ID',
	`protocol_type` VARCHAR(128) NULL DEFAULT NULL COMMENT '协议类型tcp/udp/http/dubbo',
	`parse_fun` VARCHAR(128) NULL DEFAULT NULL COMMENT '解析组件名称',
	`create_time` TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
	PRIMARY KEY (`mid`),
	INDEX `uuid` (`msg_uuid`)
)
COLLATE='utf8_general_ci'
ENGINE=InnoDB
AUTO_INCREMENT=1
;
```

