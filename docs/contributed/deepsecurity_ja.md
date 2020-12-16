# es_loaderでDeepSecurityのログを取り込む

以下の仕組みで、DeepSecurityのログをSIEMに取り込んでいきます。

1. ec2 instance上で動作しているDeepSecurity → syslogで/var/log/dsa.logにログを出力
2. td-agent/fluentdで/var/log/dsa.log → s3 bucketに転送
3. lambda functionで動作するes loaderでs3を読み取って、Elasticsearchにloadする

## DeepSecurityでのlocalhostへのsyslog転送

DeepSecurity SaaSの管理画面にloginし、Adminitration -> System Settings -> Event Forwardingで、SIEMに127.0.0.1 514/udp Local1 falicityにCommonEventFormatでログを直接転送する設定を行っておきます。
Agent should forward logs: Directory to the Syslog Server

## rsyslogで/var/log/dsa.logにDeepSecurityのログを保存
CEF:やLEEF:を含むログをDeepSecurityのログとして、/var/log/dsa.logに保存します。

/etc/rsyslog.d/ds_agent.conf
```
$FileCreateMode 0644

:syslogtag, contains, "CEF:" /var/log/dsa.log
& stop

:syslogtag, contains, "LEEF:" /var/log/dsa.log
& stop
```

## td-agent/fluendからS3へのlog転送

td-agentを用いて、S3にログを転送します。

/etc/td-agent/conf.d/ds_agent.conf
```
<source>
  @type    tail
  format   none
  path     /var/log/dsa.log
  pos_file /var/log/td-agent/.dsa.pos
  tag      ds_agent.*
</source>

<filter ds_agent.**>
  @type record_transformer
  @id ds_agent_record_modifier
  enable_ruby true
  <record>
    hostname "#{Socket.gethostname}"
    timestamp ${time.strftime('%FT%T%:z')}
    tag ${tag}
  </record>
</filter>

<match ds_agent.**>
  @type s3
  @id ds_agent_s3
  s3_bucket             ${BUCKET_NAME}
  s3_region             ${REGION}
  s3_object_key_format  %{path}%{time_slice}_${hostname}_%{index}.%{file_extension}
  path                  ds_agent/
  time_slice_format     %Y/%m/%d/%H
  timezone              Asia/Tokyo
  output_time           false
  output_tag            false
  <buffer tag,time>
    @type               file
    path                /var/log/td-agent/buffer/s3_ds_agent
    flush_mode          interval
    flush_interval      1m
    flush_at_shutdown   true
  </buffer>
</match>
```

ec2 instanceからのs3への書き込みは、instance profileで許可をしてあげると良いです。
https://aws.amazon.com/jp/premiumsupport/knowledge-center/ec2-instance-access-s3-bucket/

## elasticsearchでのlog-deepsecurity templateの定義

```
PUT _template/log-deepsecurity
{
  "log-deepsecurity" : {
    "index_patterns" : [
      "log-deepsecurity*"
    ],
    "mappings" : {
      "properties" : {
        "cloud.account" : {
          "type" : "object"
        },
        "event.severity" : {
          "type" : "integer"
        },
        "event.original" : {
          "type" : "text"
        },
        "event.count" : {
          "type" : "integer"
        },
        "timestamp" : {
          "type" : "date"
        }
      }
    }
  }
}
```

## es_loader側の設定

aws.ini/user.iniに以下を定義します。
```
[deepsecurity]
index = log-deepsecurity
s3_key = ds_agent
format = json
script_ecs = event.action destination.ip destination.port destination.mac destination.bytes source.ip source.port source.mac source.bytes network.transport event.action server.name file.path event.count rule.category host.id event.original
event.action = act
destination.ip = dst
destination.port = dpt
destination.mac = dmac
destination.bytes = out
source.ip = src
source.port = spt
source.mac = smac
source.bytes = in
network.transport = proto
server.name = fluent_hostname
file.path = fname
event.count = cnt
rule.category = cs1
host.id = cn1
event.original = msg
```

lambda functionに、deepsecurityのlogを解釈する siem/sf_deepsecurity.py が存在していることを確認してください。
ここまでの設定で、Elasticsearchにログがloadされていくはずです。


