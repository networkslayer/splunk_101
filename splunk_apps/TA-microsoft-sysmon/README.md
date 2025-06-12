# TA-Microsoft-Sysmon

* Original Author: Adrian Hall
* Current maintainers: Splunkworks

## Update History

## 10.6.2

* March 8, 2020
* Fixes minor AppInspect failures
* <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>

## 10.6.1

* March 6, 2020
* <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>

## 10.5.0

* March 3, 2020
* <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
* Reverted change to source (XmlWinEventLog...), added source specification in inputs.conf to remeove dependancy on Splunk_TA_windows

## 10.4.0

* March 2, 2020
* Tested with Sysmon version 10
* <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
* Updated props.conf

## 10.3.0

* February 20, 2020
* Tested with Sysmon version 10
* <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
* Fixed DNS eventtype to use source rather than sourcetype

## 10.2.0

* February 9, 2020
* Tested with Sysmon version 10
* <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
* Added Event Type [ms-sysmon-dns], to capture EventCode=22 Sysmon events as DNS events.
* Added network/resolution/dns tags for event type [ms-sysmon-dns].
* Added FIELDALIAS for query/reply_code_id for CIM compatibility.
* Added transform entry [extract_dns_record_data] to extract record info for DNS responses like CNAME.  Added transform entry [extract_dns_ip_data] to properly extract IP addresses from DNS responses.

## 10.1.0

* July 30, 2019
* Tested with Sysmon version 10
* <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
* Updates to work with the new Splunk_TA_windows v5 and onwards - <https://docs.splunk.com/Documentation/WindowsAddOn/5.0.1/User/Upgrade#Upgrade_from_version_4.8.4_to_version_5.0.1>
* All searches,reports and dashboards using sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" need to use source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" instead, due to the upgrade to Splunk_TA_windows v5

## 10.0.0

* June 13, 2019
* Tested with Sysmon version 10
* <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
* Added support for Sysmon v10 having new DNS Query event type.
* Provided inputs.conf examples enabling blacklist of multiple DNS Query events based on complex rule groups

## 8.1.0

* December 11, 2018
* Tested with Sysmon version 8.0
* <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>
* Updates to work with the new Splunk Enpoint Data Model - http://docs.splunk.com/Documentation/CIM/4.12.0/User/Endpoint
* Thanks to Bhavin Patel for contributions (@patel-bhavin)

## 8.0.0

* July 11, 2018
* Tested with Sysmon version 8.0
* <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>

## 6.0.8

* June 8, 2018
* Tested with Sysmon version 6.20
* <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>

## 6.0.7

* Nov 24, 2017
* Tested with Sysmon version 6.20
* <https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon>

## 6.0.6

* Nov 22, 2017
* Added FIELDALIAS for EventID/EventCode for compatibility with Sigma rules.
* <https://github.com/Neo23x0/sigma>

## 6.0.5

* Sep 12, 2017
* Support for new features of Sysmon v6.10

## 6.0.4

* Sep 9, 2017
* Prep for Splunk certification.

## 6.0.3

* Typo corrected.
* Special thanks to David Dorsey (<https://github.com/trogdorsey)> for this contribution.

## 6.0.2

* Field extractions added including but not limited to cmdline, parent_process,
* and parent_process_id.
* Special thanks to David Dorsey (<https://github.com/trogdorsey)> for this contribution.

## 6.0.1

* Field extractions for MD5, SHA1, SHA256, IMPHASH
* Special thanks to David Staulcup (<https://github.com/dstaulcu)> for ongoing assistance and contributions

## 6.0.0

* Updates to support sysmon V6
* Special thanks to David Staulcup (<https://github.com/dstaulcu)> for ongoing assistance and contributions

## 5.0.0

* Updates to support sysmon V5
* Note the sample configuration included below was modified to exclued the
* ImageLoad section which was found to be causing BSOD on some Windows 7 test systems.
* Special thanks to David Staulcup (<https://github.com/dstaulcu)> for ongoing assistance and contributions

## 4.0.0

* Minor updates to support Sysmon V4 and optimize the hash field extraction.

## 3.2.3

* Minor updates to add workflow actions via pull request and subsequent fine tuning.

## 3.2.2

* Minor updates to extract various hash values into individual fields for convenience:

## 3.2.1

* Minor updates to align with sysmon version 3.21. For details see:

## 3.1.1

* Major modification of the version to better align with SplunkBase.
* Fixed typos in eventtypes.conf and props.conf

## 0.3.1

* Lookup table added to support Sysmon 3.1
* Additional CIM compliance added
* Example config added
* Revved to version 0.3.1 to match current Sysmon version

## Using this TA

Configuration: Install TA via GUI on all search heads, install via your preferred method (manual or Deployment Server) on forwarders running on Windows that have Sysmon 3.1 or greater installed.

Ensure that you have at least version 6.2.0 universal forwarders to take advantage of Windows XML event log format.
  
Sysmon ProcessCreate events may pick up passwords in CommandLine and ParentCommandLine fields. Depending on organizational policy you may be required to mask passwords either at search time or prior to indexing. SEDCMD entries can be added to props.conf files on search heads or indexers to mask data in known positions of passwords. Note this contribution has not been widely tested and may require substantial additional configuration and tuning effort. Use at your own risk.

```bash
SEDCMD-pwd_rule1 = s/ -pw ([^\s\<])+/ -pw ***MASK***/g
```

The Sysmon v10 configuration XML spec does not allow for mutiple log-write exclusions based on rule groups.  It is possible to achieve complex log forwarding exclusions for high volume DNS Query Events with inputs.conf blacklist specs. See comments in inputs.conf for implementation examples.

For additional info on Sysmon see: <http://blogs.splunk.com/2014/11/24/monitoring-network-traffic-with-sysmon-and-splunk/>

## Support

This is a community supported TA. As such, post to answers.splunk.com and reference it.

## Recommended Configuration

We strongly recommend that you use the popular Sysmon configuration shared by SwiftOnSecurity as your starting point:

<https://github.com/SwiftOnSecurity/sysmon-config>

## Previously Recommended Configuration

*3/16/2017* - The following configuration guidance was included historically
but should now be considered deprecated. We suggest instead that you use the
SwiftOnSecurity configuration as a starting point, and tune it to meet your needs.
You may choose to use elements of the legacy configuration below, particularly if
you are interested in excluding common Splunk image/file names from creating Sysmon
events.

*NOTE:* If you choose to exclude certain events based on file name, please be aware
that this could potentially be abused by an attacker to hide malicious activity by
choosing an excluded name for their malware. If you are not willing to accept this
risk, do not use the configuration below.

Sysmon is capable of delivering a large amount of events into your
Splunk instance. The following configuration, loaded into each
system running Sysmon 3.1 or greater, will reduce the amount of data considerably.
Special thanks go to Jeff Walzer from the University of Pittsburgh for
originally helping to test this (walzer@pitt.edu).

Load this via sysmon -c (filename) from an admin-level command prompt.
(after you have placed it in a text file). You may get some
unusual errors - these are benign and can be ignored. Check the
filtering via a "sysmon -c" with no argument.

For additional Sysmon filtering, remove the entire ImageLoad section.

```xml
<Sysmon schemaversion="3.2">
  <HashAlgorithms>*</HashAlgorithms>
  <EventFiltering>
    <!-- Log all drivers except if the signature -->
    <!-- contains Microsoft or Windows -->
    <DriverLoad onmatch="exclude">
      <Signature condition="contains">microsoft</Signature>
      <Signature condition="contains">windows</Signature>
    </DriverLoad>
    <!-- Exclude certain processes that cause high event volumes -->
    <ProcessCreate onmatch="exclude">
      <Image condition="contains">splunk</Image>
      <Image condition="contains">streamfwd</Image>
      <Image condition="contains">splunkd</Image>
      <Image condition="contains">splunkD</Image>
      <Image condition="contains">splunk</Image>
      <Image condition="contains">splunk-optimize</Image>
      <Image condition="contains">splunk-MonitorNoHandle</Image>
      <Image condition="contains">splunk-admon</Image>
      <Image condition="contains">splunk-netmon</Image>
      <Image condition="contains">splunk-regmon</Image>
      <Image condition="contains">splunk-winprintmon</Image>
      <Image condition="contains">btool</Image>
      <Image condition="contains">PYTHON</Image>
    </ProcessCreate>
    <ProcessTerminate onmatch="exclude">
      <Image condition="contains">splunk</Image>
      <Image condition="contains">streamfwd</Image>
      <Image condition="contains">splunkd</Image>
      <Image condition="contains">splunkD</Image>
      <Image condition="contains">splunk</Image>
      <Image condition="contains">splunk-optimize</Image>
      <Image condition="contains">splunk-MonitorNoHandle</Image>
      <Image condition="contains">splunk-admon</Image>
      <Image condition="contains">splunk-netmon</Image>
      <Image condition="contains">splunk-regmon</Image>
      <Image condition="contains">splunk-winprintmon</Image>
      <Image condition="contains">btool</Image>
      <Image condition="contains">PYTHON</Image>
    </ProcessTerminate>
    <FileCreateTime onmatch="exclude">
      <Image condition="contains">splunk</Image>
      <Image condition="contains">streamfwd</Image>
      <Image condition="contains">splunkd</Image>
      <Image condition="contains">splunkD</Image>
      <Image condition="contains">splunk</Image>
      <Image condition="contains">splunk-optimize</Image>
      <Image condition="contains">splunk-MonitorNoHandle</Image>
      <Image condition="contains">splunk-admon</Image>
      <Image condition="contains">splunk-netmon</Image>
      <Image condition="contains">splunk-regmon</Image>
      <Image condition="contains">splunk-winprintmon</Image>
      <Image condition="contains">btool</Image>
      <Image condition="contains">PYTHON</Image>
    </FileCreateTime>
  </EventFiltering>
</Sysmon>
```
