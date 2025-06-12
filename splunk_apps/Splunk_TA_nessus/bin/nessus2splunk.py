'''
Copyright (C) 2009-2012 Splunk Inc. All Rights Reserved.
'''
# Native Imports
import argparse
import hashlib
import lxml
import lxml.etree
import operator
import os
import re
import shutil 
import string
import sys
import textwrap
import splunktalib.defusedxml.sax as dsax
import splunktalib.defusedxml.lxml as dlxml
import json
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
import glob
# Custom Imports
import nessusclienthandler
import nessusclienthandler2  # Used for the version 2 of the Nessus file parser

from splunktalib.common import log
import logging

_LOGGER = log.Logs().get_logger("ta_nessus", level=logging.DEBUG)

class PathType(object):
    '''Class for use as an argument type in an ArgumentParser.
    The __call__ function will validate whether the directory passed as the
    argument exists.
    '''

    def __call__(self, val):
        '''Returns a correctly formatted path for the current version of the OS.
        If the path does not exist or is not readable, raises ArgumentTypeError.
        '''
        val = os.path.normpath(val)
        if os.path.isdir(val):
            return val
        else:
            raise argparse.ArgumentTypeError("Invalid path specified ($SPLUNK_HOME may not be set).")


def GetOptions(argv=None):

    desc = '''
    Script for converting Nessus v1 and v2 reports into Splunk-compatible format.
            
    Intended to be run as a scripted input via inputs.conf.
        
    Example of use in inputs.conf:
    
        [script://./bin/nessus2splunk.py]
        disabled = false
        interval = 120
        index = _internal
        source = nessus2splunk
        sourcetype = nessus2splunk

    Example of use in inputs.conf using custom source directory.
    for input and output files:
    
        [script://./bin/nessus2splunk.py -s /opt/nessus/incoming]
        disabled = false
        interval = 120
        index = _internal
        source = nessus2splunk
        sourcetype = nessus2splunk
    
    srcdir argument must be either:
    
    - Fully qualified paths from the root directory, OR
    - A relative path, relative to the app directory.
        

    '''

    parser = argparse.ArgumentParser(description=textwrap.dedent(desc),
        formatter_class=argparse.RawDescriptionHelpFormatter)

    # Set the default directory for input files.    
    grandparent = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    input_default = os.path.join(grandparent, 'Splunk_TA_nessus', 'spool')

    parser.add_argument('-s', '--srcdir',
        dest='srcdir',
        type=PathType(),
        action='store',
        help='The source directory for locating Nessus data files.',
        default=input_default)

    parser.add_argument('-l', '--loglevel',
        dest='loglevel',
        type=str,
        action='store',
        help='The debug level for log, including debug, warn & error',
        default="WARN")

    parser.add_argument('-p', '--pluginoutput',
        dest='pluginoutput',
        type=bool,
        action='store',
        help='If need to index the plugin_output element',
        default=False)
    
    return parser.parse_args(argv)


def ParseReport(filePath):
    # Open the nessus file
    nessusFile = open(filePath, 'r')

    # Read entire file into list
    nessusFileList = nessusFile.readlines()
    nessusFileXML = string.join(nessusFileList, '')
    #print nessusFileXML
        
    nessusFile.close()

    if DetermineVersion(nessusFileXML) == 2:
        return ParseReportXMLver2(nessusFileXML, filePath)
    else:
        return ParseReportXMLver1(nessusFileXML, filePath)


def DetermineVersion(nessusFileXML):
    v2Regx = re.compile('\<NessusClientData_v2\>')
    
    if v2Regx.search(nessusFileXML) is not None:
        return 2
    else:
        return 1
    
    
def ParseReportXMLver2(reportXMLString, filePath=None):
    # Hash File
    h = hashlib.sha1()
    h.update(reportXMLString)
    hashval = h.hexdigest()
    
    # Note: We are not parsing the Targets or Policies sections at the top level
    # Instead we are parsing the Targets and Policy objects (subsections) within the top level report section
    # We could parse these sections with additional code if necessary
    
    # Parse Report
    reportParser = dsax.make_parser()
    reportHandler = nessusclienthandler2.NessusReportHandler()
    reportParser.setContentHandler(reportHandler)
    dsax.parseString(reportXMLString, reportHandler)
    #pprint.pprint(reportHandler.report)
    report = reportHandler.report

    # Parse Report Policy 
    policyParser = dsax.make_parser()
    policyHandler = nessusclienthandler2.NessusPoliciesHandler()
    policyParser.setContentHandler(policyHandler)
    dsax.parseString(reportXMLString, policyHandler)
    #pprint.pprint(policyHandler.policies)
    report['Policy'] = policyHandler.policies
    
    if filePath is not None:
        report['FileName'] = filePath
    
    report['FileHash'] = hashval
    
    # Populate the PluginSelection
    for i in report['Policy'][0]['ServerPreferences']:
        if _getChildKey(report['Policy'][0]['ServerPreferences'][i], 'Name') == 'plugin_set':
            report['PluginSelection'] = _getChildKey(report['Policy'][0]['ServerPreferences'][i], 'Value').split(";")
    
    # Populate the report name
    #report['ReportName'] = report['ReportHosts'][0]
    
    # Populate StartTime, EndTime
    if len(report['ReportHosts']) > 0:
        report['StartTime'] = _getChildKey(report['ReportHosts'][0], 'StartTime')
        report['StopTime'] = _getChildKey(report['ReportHosts'][-1], 'EndTime')
    
    # Parse Report Targets
    import ipmath
    targets = []
    
    for i in report['Policy'][0]['ServerPreferences']:
        if _getChildKey(report['Policy'][0]['ServerPreferences'][i], 'Name') == 'TARGET':
            target = _getChildKey(report['Policy'][0]['ServerPreferences'][i], 'Value').split(",")
            ipRegex = re.compile('\d+\.\d+\.\d+\.\d+')
            netRegex = re.compile('(\d+\.\d+\.\d+\.\d+/\d+)')
            rangeRegex = re.compile('\d+\.\d+\.\d+\.\d+\-\d+\.\d+\.\d+\.\d+')
            
            for t in target:
                if len(t.strip()) > 0:
                    entry = {}
                    ipMatch = ipRegex.match(t)
                    netMatch = netRegex.match(t)
                    rangeMatch = rangeRegex.match(t)
                    
                    #If a range
                    ipRange = t.split("-")
                    
                    if len(ipRange) >= 2 and rangeMatch:
                        entry['StartAddress'] = ipmath.IPToLong(ipRange[0])
                        entry['EndAddress'] = ipmath.IPToLong(ipRange[1])
                        entry['Type'] = 'range'
                        
                    #If a netmasked range
                    elif netMatch:
                        tempRange = ipmath.CIDRToRange(netMatch.group(1))
                        entry['StartAddress'] = ipmath.IPToLong(tempRange['startAddress'])
                        entry['EndAddress'] = ipmath.IPToLong(tempRange['endAddress'])
                        entry['Type'] = "range"
                        
                    #If an IP
                    elif ipMatch:
                        entry['StartAddress'] = ipmath.IPToLong(ipMatch.group())
                        entry['EndAddress'] = ipmath.IPToLong(ipMatch.group())
                        entry['Type'] = "ip"
                        
                    #If a host name
                    else:
                        entry['Hostname'] = t
                    
                    entry['Selected'] = "1"
                    
                    targets.append(entry)
    
    report['Targets'] = targets
    
    # Return reports
    return [report]
    
    
def ParseReportXMLver1(nessusFileXML, filePath=None):
    # It is important to split the nessus file into it's 3 sections (Targets, Policies, Report)
    # Nessus adds complication by also placing a "Targets" and "Policy" (not Policies) object within the Report section
    
    # Declaring report section variables here:
    reportXML = {}              # dictionary containing multiple report xml data
    reports = []                # dictionary containing multiple parsed reports

    reportStartIndex = {}       # dictionary for start index
    reportStartCount = 0        # counter for start indexes dictionary entries

    reportEndIndex = {}         # dictionary for end index
    reportEndCount = 0          # counter for end index dictionary entries
    
    # Hash File - unused (why?)
    #h = hashlib.md5()
    #h.update(nessusFileXML)
    #hashval = h.hexdigest()

    # Discover where report sections begin
    reportStartRegx = re.compile('\<Report\>')
    reportStartIterator = reportStartRegx.finditer(nessusFileXML)

    if reportStartIterator:
        
        for match in reportStartIterator:
            
            tempSpan = match.span()
            reportStartIndex[reportStartCount] = tempSpan[0]
            reportStartCount += 1
    
    # Discover where report sections end
    reportEndRegx = re.compile('\<\/Report\>')
    reportEndIterator = reportEndRegx.finditer(nessusFileXML)

    if reportEndIterator:
        
        for match in reportEndIterator:
            
            tempSpan = match.span()
            reportEndIndex[reportEndCount] = tempSpan[1]
            reportEndCount += 1

    # Populate reportXML dictionary with XML from each report
    for x in range(0, reportStartCount):

        reportXML = nessusFileXML[reportStartIndex[x]:reportEndIndex[x]]

        # Note: We are not parsing the Targets or Policies sections at the top level
        # Instead we are parsing the Targets and Policy objects (subsections) within the top level report section
        # We could parse these sections with additional code if necessary
        
        # Parse Report
        reportParser = dsax.make_parser()
        reportHandler = nessusclienthandler.NessusReportHandler()
        reportParser.setContentHandler(reportHandler)
        dsax.parseString(reportXML, reportHandler)
        #pprint.pprint(reportHandler.report)
        reports.append(reportHandler.report)

        # Parse Report Targets
        #targetsParser = dsax.make_parser()
        #targetsHandler = nessusclienthandler.NessusTargetsHandler()
        #targetsParser.setContentHandler(targetsHandler)
        #dsax.parseString(reportXMLString, targetsHandler)
        #pprint.pprint(targetsHandler.targets)
        #reports['Targets'] = targetsHandler.targets

        # Parse Report Policy 
        #policyParser = dsax.make_parser()
        #policyHandler = nessusclienthandler.NessusPoliciesHandler()
        #policyParser.setContentHandler(policyHandler)
        #dsax.parseString(reportXMLString, policyHandler)
        #pprint.pprint(policyHandler.policies)
        #reports['Policy'] = policyHandler.policies
        
        #if filePath is not None:
        #    reports['FileName'] = filePath
        
        #reports['FileHash'] = hash
        
    # Return reports
    return reports


def GetFields():
    '''Return the set of single-valued report field mappings as a list of 
    tuples (field, key, mapping function, isRequired).'''
    return [('start_time', 'StartTime', str, True),
            ('end_time', 'EndTime', str, True),
            ('dest_dns', 'DNSName', lambda x: str(x).strip('\.'), False),
            ('dest_nt_host', 'NetbiosName', str, False),
            ('dest_mac', 'MacAddress', str, False),
            ('dest_ip', 'HostName', str, False),
            ('os', 'OSName', lambda x: [i.group(1) for i in re.finditer('([^\r\n]+)', x)], False)
        ]


def GetSubFields():
    '''Return the set of single-valued subreport field mappings as a list of tuples (field, key, mapping function).'''
    
    # operator.methodcaller is used here so that any string will be handled;
    # str.split and unicode.split work on only one type of string.
    return [('cvss_base_score', 'CvssBaseScore', str),
            ('cvss_temporal_score', 'CvssTemporalScore', str),
            ('cvss_temporal_vector', 'CvssTemporalVector', str),
            ('cvss_vector', 'CvssVector', str),
            ('dest_port_proto', 'Port', str),
            ('severity_id', 'Severity', str),
            ('signature_family', 'PluginFamily', str),
            ('signature_id', 'PluginID', str),
            ('signature', 'PluginName', str),
            ('bid', 'bid', operator.methodcaller('split')),
            ('cve', 'cve', operator.methodcaller('split')),
            ('cwe', 'cwe', operator.methodcaller('split')),
            ('osvdb', 'osvdb', operator.methodcaller('split')),
            ('xref', 'xref', operator.methodcaller('split')),
            ('solution', 'solution', str)
        ]

def _getChildKey(mydict, key):
    if key in mydict:
        return mydict[key]
    return ""

def writeCheckpoint(file_path, data):
    try:
        with open(file_path, "w+") as fp_out:
            fp_out.write(json.dumps(data))
    except Exception as e:
        raise e

def readCheckpoint(file_path):
    if os.path.isfile(file_path):
        try:
            with open(file_path, "r") as fp_in:
                data_read = fp_in.read()
                data_read_dict = json.loads(data_read)
                return data_read_dict
        except Exception as e:
            raise e
    return None

if __name__ == '__main__':
    
    # Custom LINE_BREAKER string
    LINE_BREAKER = "\r\n---splunk-ta-nessus-end-of-event---\r\n"
    
    # Maintain count of successfully processed .nessus files.
    processed = 0


    # lxml parser used for validation.
    parser = lxml.etree.XMLParser()

    # Retrieve command-line options
    options = GetOptions(sys.argv[1:])
    package_name = __file__.split(os.sep)[-3]
    checkpoint_dir_location = make_splunkhome_path(['var', 'lib', 'splunk', 'modinputs', package_name])
    checkpoint_file = os.path.join(checkpoint_dir_location, 'nessus_file_checkpoint.txt')
    if not os.path.exists(checkpoint_dir_location):
        os.makedirs(checkpoint_dir_location)
    
    # Retrieve field transformations
    #fields = GetFields()

    # setup log level
    loglevel = options.loglevel.lower().strip()
    if loglevel == "warn":
        loglevel = logging.WARN
    elif loglevel == "error":
        loglevel = logging.ERROR
    elif loglevel == "debug":
        loglevel = logging.DEBUG
    else:
        _LOGGER.warn('The input log level "%s" is invalid. Use default value "WARN"', loglevel)
        loglevel = logging.WARN

    log.Logs().set_level(loglevel)
    data_read_dict = readCheckpoint(checkpoint_file)
    # Iterate over all .nessus files. 
    for nessusFile in os.listdir(options.srcdir):
        
        # Input file path.
        nessusFilePath = os.path.join(options.srcdir, nessusFile)
        
        # Temporary output file.
        splunkFile = nessusFilePath + '.splunk'
        
        if nessusFile.endswith('.nessus'):
            _LOGGER.debug('Processing file %s', nessusFilePath)
            file_timestamp = os.path.getmtime(nessusFilePath)
            # Validate the XML
            if not data_read_dict or file_timestamp > int(data_read_dict.get('last_timestamp')):
                with open(nessusFilePath, 'r') as fh:
                    try:
                        tree = dlxml.parse(fh, parser)
                    except lxml.etree.XMLSyntaxError as e:
                        # Invalid XML; proceed with next file.
                        _LOGGER.error('input file was not valid XML: %s', nessusFilePath)
                        continue
                    except Exception as e:
                        _LOGGER.error('unknown error while parsing XML file %s: (Exception: %s)', nessusFilePath, e)

                theReports = ParseReport(nessusFilePath)
                
                # Increment count.
                processed += 1

                
                for a in range(0, len(theReports)):
                    reportHosts = theReports[a]['ReportHosts']
                            
                    for reportHost in reportHosts:
                        reportItems = reportHost.get('ReportItems', [])
                        event = ''
                        subevent = ''
    
                        for field, key, mapper, isRequired in GetFields():
                            if len(reportHost.get(key, '')) > 0:
                                value = mapper(reportHost[key])
                                if isinstance(value, list):
                                    for v in value:
                                        event += ' %s="%s"' % (field, v)
                                elif isinstance(value, basestring):
                                    event += ' %s="%s"' % (field, value)
                                else:
                                    # Unknown mapping error.
                                    _LOGGER.error("value for field could not be mapped: %s", field)
                            else:
                                # Field value is null.
                                if isRequired:
                                    # Add a blank value
                                    event += ' %s="%s"' % (field, '')
                                else:
                                    # Field did not exist in data but is not required; ignore.
                                    pass


                        for reportItem in reportItems:
                            subevent = ''
                            
                            subfields = GetSubFields()
                            if options.pluginoutput:
                                subfields.append(
                                    ('plugin_output', 'Data', lambda x: re.sub(r"\s+", " ", re.sub(r"[\r\n]+", ", ", x)))
                                )
                            for field, key, mapper in subfields:
                                if len(reportItem.get(key, '')) > 0:
                                    value = mapper(reportItem[key])
                                    if isinstance(value, list):
                                        for v in value:
                                            subevent += ' %s="%s"' % (field, v)
                                    elif isinstance(value, basestring):
                                        subevent += ' %s="%s"' % (field, value)
                                    else:
                                        # Unknown mapping error.
                                        _LOGGER.error("value for field could not be mapped: %s", field)

                            # Write the event. Note that if a host has no
                            # reportItems, it will not be output.
                            # LINE_BREAKER includes its own newlines, no need to add them here.
                            print LINE_BREAKER + "source_value=" + nessusFilePath + ' ' + event.rstrip('\r\n') + ' ' + subevent.rstrip('\r\n')
        else:
            # This file was not a .nessus file. Do not warn since this is acceptable.
            pass

    newest = max(glob.iglob(os.path.join(options.srcdir,'*.nessus')), key=os.path.getmtime)
    newest_time = os.path.getmtime(newest)
    data_read_dict = readCheckpoint(checkpoint_file)
    if data_read_dict:
        data_read_dict['last_timestamp'] = newest_time
    else:
        data_read_dict = {'last_timestamp': newest_time}
    writeCheckpoint(checkpoint_file, data_read_dict)
    # End for loop
    if processed == 0:
        # _LOGGER.warn('no files in .nessus format were found in the source directory: %s', options.srcdir)
        pass
