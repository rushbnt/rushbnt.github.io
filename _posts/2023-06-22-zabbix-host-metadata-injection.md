---
title: "[Back to 2022] Zabbix Auto registration host metadata injection"
categories:
  - Bug analysis
tags:
  - 0day
  - zabbix
  - analysis
  - ZDI-CAN-16753
---

## TL;DR
This is an old bug which I discovered in the beginning of last year. I waited so long for zabbix handling, so I decided write this blog to share an easy case.

## Overview
Zabbix is an open-source software tool to monitor IT infrastructure such as networks, servers, virtual machines, and cloud services. Zabbix contains some main components:
- __Zabbix Server__: The Server can remotely check networked services (such as web servers and mail servers) using simple service checks, but it is also the central component to which the Agents will report availability and integrity information and statistics.
- __Zabbix Proxy__: Zabbix Proxy is an ideal solution for a centralized monitoring of remote locations, branches, networks having no local administrators.
- __Zabbix Agent__: The Agent will gather operational information from the system on which it is running, and report these data to the Zabbix for further processing.
- __Zabbix Frontend__: It is for management.

## Vulnerability
I am only focus the Zabbix Agent at starting time As usual, I went audit the some structure of data first. But I did not find exploitable points after 2-3 weeks. I was discouraging because this is the first time I had tried with a realworld target. It is my fault for not reading the docs carefully and missed some attack surfaces. After realizing the mistake, I started read all document of Zabbix and some Zabbix's vulnerabilities report. It has a stuff call as [Auto registration](https://www.zabbix.com/documentation/5.0/en/manual/discovery/auto_registration) which make [RCE](https://support.zabbix.com/browse/ZBX-12075?focusedCommentId=226988&page=com.atlassian.jira.plugin.system.issuetabpanels%3Acomment-tabpanel). The main things is injection into the macro. Follow the [doc](https://www.zabbix.com/documentation/5.0/en/manual/appendix/macros/supported_by_location), we have alot of macro, one of them is `{HOST.METADATA}`:
```
→ Autoregistration notifications and commands 
Host metadata: Used only for active agent autoregistration. Supported since 2.2.0.
```

## Exploit strategy
Firstly, we need understand the struct of packet:
```c
struct protocol_packet{
    char[4] header;             // = "ZBXD"
    char protocol_version;
    zbx_uint32_t expected_len;  // = len of packet's data when normal protocol_version
    zbx_uint32_t reserved;      // = len data when using compress protocol_version
    ... data
}
```
With `data` is a json with `request` field for determine the type of request. We only need the inject the special characters to escape the command in this setup script.

## Conclusion
It is 2 months with first time audit the sourcecode of a realworld project and got the first bounty, I realized some easy way to make different. Should find as much as possible the attack surface to increase our change. :))
