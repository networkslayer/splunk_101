FROM splunk/splunk:latest

ENV SPLUNK_START_ARGS=--accept-license \
    SPLUNK_PASSWORD=changeme

COPY splunk_apps/utbox /opt/splunk/etc/apps/utbox
COPY splunk_apps/splunk_app_stream /opt/splunk/etc/apps/splunk_app_stream
COPY splunk_apps/Splunk_TA_fortinet_fortigate /opt/splunk/etc/apps/Splunk_TA_fortinet_fortigate
COPY splunk_apps/Splunk_TA_nessus /opt/splunk/etc/apps/Splunk_TA_nessus
COPY splunk_apps/Splunk_TA_windows /opt/splunk/etc/apps/Splunk_TA_windows
COPY splunk_apps/TA-microsoft-sysmon /opt/splunk/etc/apps/TA-microsoft-sysmon
COPY splunk_apps/TA-Suricata /opt/splunk/etc/apps/TA-Suricata
COPY splunk_apps/botsv1_data_set /opt/splunk/etc/apps/botsv1_data_set



