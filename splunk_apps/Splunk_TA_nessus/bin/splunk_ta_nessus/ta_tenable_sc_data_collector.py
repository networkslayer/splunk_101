import time
import json
import httplib2

import splunktalib.common.util as util

import splunktaucclib.data_collection.ta_data_client as dc
import splunktaucclib.data_collection.ta_consts as c
import splunktaucclib.common.log as stulog

import ta_tenable_consts as consts
import ta_tenable_util
import security_center


@dc.client_adatper
def do_job_one_time(all_conf_contents, task_config, ckpt):
    return _do_job_one_time(all_conf_contents, task_config, ckpt)


def _do_job_one_time(all_conf_contents, task_config, ckpt):
    logger_prefix = _get_logger_prefix(task_config)
    stulog.logger.info("{} Enter _do_job_one_time().".format(logger_prefix))
    server_info = _get_server_info(all_conf_contents, task_config)
    url = server_info.get(consts.url)
    username = server_info.get(consts.username)
    password = server_info.get(consts.password)
    release_session = util.is_true(server_info.get(consts.release_session, False))
    ingest_only_completed_scans = util.is_true(server_info.get(consts.ingest_only_completed_scans, False))

    proxy_config = all_conf_contents[consts.global_settings][
        consts.nessus_proxy]
    enabled = util.is_true(proxy_config.get('proxy_enabled', ''))

    tenable_sc_settings = all_conf_contents[consts.global_settings][
        consts.tenable_sc_settings]
    disable_ssl_certificate_validation = util.is_true(tenable_sc_settings.get(
        'disable_ssl_certificate_validation'))
    stulog.logger.info(
        '{} The disable_ssl_certificate_validation is {}'.format(
            logger_prefix, disable_ssl_certificate_validation))
    stulog.logger.info(
        '{} The ingest_only_completed_scans is {}'.format(
            logger_prefix, ingest_only_completed_scans))
    try:
        if not enabled:
            stulog.logger.info("{} Proxy is disabled.".format(logger_prefix))
            proxy_config = None
        else:
            stulog.logger.info("{} Proxy is enabled.".format(logger_prefix))
            
        sc = security_center.get_security_center(
            url,
            disable_ssl_certificate_validation,
            username,
            password,
            proxy_config,
            logger_prefix=logger_prefix,
            release_session=release_session)
            
    except httplib2.SSLHandshakeError:
        stulog.logger.error(
            "{} [SSL: CERTIFICATE_VERIFY_FAILED] certificate verification failed. "
            "The certificate validation is enabled. "
            "You may need to check the certificate and "
            "refer to the documentation and add it to the trust list.".format(
                logger_prefix, url))
        raise Exception

    # According to the data value, invoke different method
    data = task_config.get(c.data)
    stulog.logger.info("{} The data field for tenable_sc_inputs is {}".format(
        logger_prefix, data))
    if data == consts.sc_vulnerability:
        return _process_sc_vulnerability(sc, task_config, ckpt, server_info,
                                         logger_prefix, ingest_only_completed_scans)
    else:
        raise Exception('Cannot process data={}'.format(data))
    stulog.logger.info("{} Exit _do_job_one_time().".format(logger_prefix))


def _get_server_info(global_config, task_config):
    server_name = task_config[consts.server]
    return global_config[consts.servers][server_name]


def cmp2(x, y):
    try:
        return cmp(int(x), int(y))
    except ValueError:
        return cmp(x, y)


def _process_sc_vulnerability(sc, task_config, ckpt, server_info,
                              logger_prefix, ingest_only_completed_scans=False):
    _pre_process_ckpt(sc, task_config, ckpt, logger_prefix)
    stop = yield None, ckpt
    stulog.logger.info("{} Finish process checkpoint.".format(logger_prefix))
    if stop:
        return
    server_url = server_info.get(consts.url)
    sub_ckpt = ckpt.get(server_url)
    scan_results = sub_ckpt.get('scan_results')
    host = ta_tenable_util.extract_host(server_url)
    index = task_config.get(c.index)
    batch_size = task_config.get(c.batch_size)
    if batch_size is None:
        step = 10000
    else:
        step = int(batch_size)
    stulog.logger.info("{} The batch_size is {}.".format(logger_prefix, step))

    for scan_id in sorted(scan_results.iterkeys(), cmp=cmp2):
        scan_info = scan_results[scan_id]
        status = scan_info.get('status')
        import_status = scan_info.get('importStatus')
        #FIXME: make the retry_count configurable
        # If the value of "Status" field is "Error", then after retrying for 5 times, if the value of "Status" field
        # remains unchanged, then the scan will deleted from the checkpoint
        if scan_info.get('status') == 'Error' and int(scan_info.get('retry_count')) >= 5:
            stulog.logger.info("Deleting failed scan from checkpoint after retrying: {} for scan_id: {}".format(
                scan_info.get('retry_count'), scan_id)
            )
            del sub_ckpt['scan_results'][scan_id]

        # Filtering the scans to be considered based on ingest_only_completed_scans parameter
        if ingest_only_completed_scans and (status != "Completed"):
            stulog.logger.debug("Filtering out the scans which are not in completed state. Status of scan: {} and Scan ID: {}".format(status, scan_id))
            continue

        if (status != 'Partial' and status != 'Completed') or import_status != "Finished":
            continue
        if scan_info.get('total_records') is None:
            stulog.logger.debug("Filtering out the scans which are not having the vulnerabilities. Status of scan: {} and Scan ID: {}".format(status, scan_id))
            continue
        start_offset = scan_info.get('received')
        end_offset = scan_info.get('received')
        sourcetype = 'tenable:sc:vuln'
        source = 'scan_result_id:{}'.format(scan_id)
        try:
            scan_result = sc.get_scan_result(scan_id)
            scan_result_info = {'id': scan_id,
                                'name': scan_result.get('name'),
                                'importStart': scan_result.get('importStart'),
                                'importFinish':
                                scan_result.get('importFinish'),
                                'createdTime': scan_result.get('createdTime'),
                                'startTime': scan_result.get('startTime'),
                                'finishTime': scan_result.get('finishTime')}

            if scan_info.get('total_records') == 0 and scan_info.get("retry_count", 0) < 1:
                raw_data = {'_scan_result_info': scan_result_info,
                            '_is_scan_result_empty': 1}
                event = dc.build_event(
                    host=host,
                    source=source,
                    sourcetype=sourcetype,
                    time=scan_result_info.get('importStart'),
                    index=index,
                    raw_data=json.dumps(raw_data))
                stop = yield event, ckpt

            while scan_info.get('received') <= scan_info.get('total_records'):
                end_offset += step
                scan_vuln_details = sc.get_vulns(scan_id, start_offset, end_offset)
                vuln_list = scan_vuln_details["result"]

                # Getting the latest count of total vulnerabilities
                scan_info["total_records"] = int(scan_vuln_details["total_records"])

                # If no vulnearbilities are received
                if len(vuln_list) == 0:
                    # 1. If status of Scan is other than "Completed"
                    # 2. If status of Scan is Completed but the count of received vulnerabilities is not
                    #    matching the expected count
                    if scan_info.get("status") != "Completed" or (scan_info.get("status") == "Completed" and 
                            scan_info.get("received") < scan_info.get("total_records")):

                        scan_info.update({'retry_count': int(scan_info.get('retry_count', 0)) + 1})
                        stulog.logger.debug("Waiting for scan ID {} to get completed and ingest expected count of vulnerabilities. Status = {}, total vulnerabilities received = {}, expected count of vulnerabilities = {}, Retry Count = {}".format(
                                scan_id, status, scan_info.get("received"), scan_info.get("total_records"),
                                scan_info.get("retry_count", 0)
                            ))

                    break

                scan_info['received'] += len(vuln_list)
                stulog.logger.info("Total vulnerabilities received: {}".format(scan_info.get("received")))
                stulog.logger.debug("For Scan ID: {}, total vulnerabilities received: {}, expected count of vulnerabilities: {}".format(
                        scan_id, scan_info.get("received"), scan_info.get("total_records")
                    )
                )
                events = []
                for vuln in vuln_list:
                    vuln['_scan_result_info'] = scan_result_info
                    vuln['_is_scan_result_empty'] = 0
                    events.append(dc.build_event(host=host,
                                                 source=source,
                                                 sourcetype=sourcetype,
                                                 time=vuln.get('lastSeen'),
                                                 index=index,
                                                 raw_data=json.dumps(vuln)))
                stop = yield events, ckpt
                if stop:
                    break
                start_offset = end_offset
        except security_center.APIError as e:
            if e.error_code in (146, 147):
                stulog.logger.warn('{} error_msg={}'.format(logger_prefix,
                                                            e.error_msg))
                del sub_ckpt['scan_results'][scan_id]
            else:
                raise e


        # Checking if threshold limit is reached to wait for either:
        # 1. Scan to ingest expected count of vulnerabilities
        # 2. Scan to get completed after its expected count of vulnerabilities are ingested
        if scan_info.get("retry_count", 0) >= 5:
            stulog.logger.info("Deleting the scan_id {} from the checkpoint after retrying for {} times for scan to get completed and ingest expected count of vulnerabilities. Status: {}, total vulnerabilities of received: {}, expected count of vulnerabilities: {}".format(
                    scan_id, scan_info.get("retry_count", 0), scan_info.get("status"), scan_info.get("received"),
                    scan_info.get("total_records")
                )
            )

        # A scan will be deleted if
        #    1. Expected count of vulnerabilities are indexed and status of Scan is "Completed"
        #    2. After retrying for 5 times, either of below cases occur:
        #       -> Scan to ingest expected count of vulnerabilities
        #       -> Scan to get completed after its expected count of vulnerabilities are ingested
        if (scan_info.get("status") == "Completed" and scan_info.get('received') >= scan_info.get('total_records')) or scan_info.get("retry_count", 0) >= 5:
            del scan_results[scan_id]
            stop = yield None, ckpt
        if stop:
            return
    yield None, ckpt


def _pre_process_ckpt(sc, task_config, ckpt, logger_prefix):
    server_url = sc.get_server_url()
    start_time = task_config.get(consts.start_time)
    start_time = ta_tenable_util.iso8601_to_timestamp(start_time)
    end_time = time.time()

    if start_time > end_time:
        raise Exception(
            'The start_time must be less than or equal to end_time')
    stulog.logger.info(
        '{logger_prefix} Perform a request to {server_url}, '
        'the start time is {start_time}'.format(logger_prefix=logger_prefix,
                                                server_url=server_url,
                                                start_time=start_time))
    stulog.logger.info(
        '{logger_prefix} Perform a request to {server_url}, '
        'the end time is {end_time}'.format(logger_prefix=logger_prefix,
                                            server_url=server_url,
                                            end_time=end_time))
    sub_ckpt = ckpt.get(server_url)
    sub_ckpt = sub_ckpt if sub_ckpt else {}
    ckpt_start_time = sub_ckpt.get('start_time')
    ckpt_end_time = sub_ckpt.get('end_time')

    if start_time != ckpt_start_time:
        stulog.logger.info(
            '{} The start time in conf not equal to the start time in checkpoint, '
            'reinitialize checkpoint for {}'.format(logger_prefix, server_url))
        sub_ckpt = {}
        job_start_time = start_time
    else:
        job_start_time = ckpt_end_time + 1
    stulog.logger.info('{} The start time is {} and the end time is {}'.format(
        logger_prefix, job_start_time, end_time))
    usable_scan_result = sc.perform_request(
        'GET', 'scanResult?filter=usable&fields=importStatus,status&startTime={}&endTime={}'.format(
            job_start_time, end_time))

    sub_ckpt['start_time'] = start_time
    sub_ckpt['end_time'] = end_time
    if not sub_ckpt.get('scan_results'):
        sub_ckpt['scan_results'] = {}

    # Loop to get status of all the scans returned from the Security Center
    for scan_result in usable_scan_result.get('usable'):
        scan_id = scan_result.get('id')
        status = scan_result.get('status')
        import_status = scan_result.get('importStatus')

        if sub_ckpt['scan_results'].get(scan_id):
            sub_ckpt['scan_results'][scan_id].update({'status': status})
            sub_ckpt['scan_results'][scan_id].update({'importStatus': import_status})
            if status == 'Error':
                sub_ckpt['scan_results'][scan_id].update({'retry_count': int(sub_ckpt['scan_results'][scan_id].get('retry_count', 0)) + 1})
        else:
            if status == 'Error':
                sub_ckpt['scan_results'][scan_id] = {'status': status, 'importStatus': import_status, 'retry_count': 0}
            else:
                sub_ckpt['scan_results'][scan_id] = {'status': status, 'importStatus': import_status}

        if (status != 'Partial' and status != 'Completed') or import_status != 'Finished':
            continue

        if sub_ckpt['scan_results'][scan_id].get('total_records'):
            continue

        try:
            total_records = sc.get_total_records_for_vuln(scan_id)
            sub_ckpt['scan_results'][scan_id].update(
                {'total_records': total_records,
                 'received': 0})
        except security_center.APIError as e:
            if e.error_code in (143, 146, 147):
                stulog.logger.warn('{} error_msg={}'.format(logger_prefix,
                                                            e.error_msg))
                del sub_ckpt['scan_results'][scan_id]
            else:
                raise e

    scan_results = sub_ckpt.get('scan_results')
    for (scan_id, scan_info) in scan_results.items():
        status = scan_info.get('status')
        import_status = scan_info.get('importStatus')
        if (status == 'Partial' or status == 'Completed') and import_status == 'Finished':
            if scan_info.get('total_records') is not None:
                continue
        try:
            scan_result = sc.get_scan_result(scan_id)
            status = scan_result.get('status')
            import_status = scan_result.get('importStatus')
            if status == 'Error':
                scan_info.update({'retry_count': int(scan_info.get('retry_count', 0)) + 1})
            if (status != 'Partial' and status != 'Completed') or import_status != 'Finished':
                continue

            total_records = sc.get_total_records_for_vuln(scan_id)
            scan_info.update({'status': status,
                              'importStatus': import_status,
                              'total_records': total_records,
                              'received': 0})
        except security_center.APIError as e:
            if e.error_code in (143, 146, 147):
                stulog.logger.warn('{} error_msg={}'.format(logger_prefix,
                                                            e.error_msg))
                del sub_ckpt['scan_results'][scan_id]
            else:
                raise e

    ckpt[server_url] = sub_ckpt


def _get_logger_prefix(task_config):
    pairs = ['{}="{}"'.format(c.stanza_name, task_config[c.stanza_name])]
    for key in task_config[c.divide_key]:
        pairs.append('{}="{}"'.format(key, task_config[key]))
    return "[{}]".format(" ".join(pairs))
