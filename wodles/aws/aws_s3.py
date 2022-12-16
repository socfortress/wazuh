#!/usr/bin/env python3

# Import AWS S3
#
# Copyright (C) 2015, Wazuh Inc.
# Copyright: GPLv3
#
# Updated by Jeremy Phillips <jeremy@uranusbytes.com>
#
# Error Codes:
#   1 - Unknown
#   2 - SIGINT
#   3 - Invalid credentials to access S3 bucket
#   4 - boto3 module missing
#   5 - Unexpected error accessing SQLite DB
#   6 - Unable to create SQLite DB
#   7 - Unexpected error querying/working with objects in S3
#   8 - Failed to decompress file
#   9 - Failed to parse file
#   11 - Unable to connect to Wazuh
#   12 - Invalid type of bucket
#   13 - Unexpected error sending message to Wazuh
#   14 - Empty bucket
#   15 - Invalid endpoint URL
#   16 - Throttling error
#   17 - Invalid key format
#   18 - Invalid prefix
#   19 - The server datetime and datetime of the AWS environment differ

import argparse
import configparser
import signal
import sys
from os import path
from datetime import datetime

import buckets_s3
import services


DEFAULT_AWS_CONFIG_PATH = path.join(path.expanduser('~'), '.aws', 'config')
CREDENTIALS_URL = 'https://documentation.wazuh.com/current/amazon/services/prerequisites/credentials.html'
DEPRECATED_MESSAGE = 'The {name} authentication parameter was deprecated in {release}. ' \
                     'Please use another authentication method instead. Check {url} for more information.'

ALL_REGIONS = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-1', 'ap-northeast-2',
               'ap-southeast-2', 'ap-south-1', 'eu-central-1', 'eu-west-1']

# Enable/disable debug mode
debug_level = 0


def handler(signal, frame):
    print("ERROR: SIGINT received.")
    sys.exit(2)


def debug(msg, msg_level):
    if debug_level >= msg_level:
        print('DEBUG: {debug_msg}'.format(debug_msg=msg))


def arg_valid_date(arg_string):
    try:
        parsed_date = datetime.strptime(arg_string, "%Y-%b-%d")
        # Return str created from date in YYYYMMDD format
        return parsed_date.strftime('%Y%m%d')
    except ValueError:
        raise argparse.ArgumentTypeError("Argument not a valid date in format YYYY-MMM-DD: '{0}'.".format(arg_string))


def arg_valid_prefix(arg_string):
    if arg_string and arg_string[-1] != '/' and arg_string[-1] != "\\":
        return '{arg_string}/'.format(arg_string=arg_string)
    return arg_string


def arg_valid_accountid(arg_string):
    if arg_string is None:
        return []
    account_ids = arg_string.split(',')
    for account in account_ids:
        if not account.strip().isdigit() or len(account) != 12:
            raise argparse.ArgumentTypeError(
                "Not valid AWS account ID (numeric digits only): '{0}'.".format(arg_string))

    return account_ids


def arg_valid_regions(arg_string):
    if not arg_string:
        return []
    final_regions = []
    regions = arg_string.split(',')
    for arg_region in regions:
        if arg_region.strip():
            final_regions.append(arg_region.strip())
    return final_regions


def arg_valid_iam_role_duration(arg_string):
    """Checks if the role session duration specified is a valid parameter.

    Parameters
    ----------
    arg_string: str or None
        The desired session duration in seconds.

    Returns
    -------
    num_seconds: None or int
        The returned value will be None if no duration was specified or if it was an invalid value; elsewhere,
        it will return the number of seconds that the session will last.

    Raises
    ------
    argparse.ArgumentTypeError
        If the number provided is not in the expected range.
    """
    # Session duration must be between 15m and 12h
    if not (arg_string is None or (900 <= int(arg_string) <= 3600)):
        raise argparse.ArgumentTypeError("Invalid session duration specified. Value must be between 900 and 3600.")
    return int(arg_string)

def get_aws_config_params() -> configparser.RawConfigParser:
    """Read and retrieve parameters from aws config file

    Returns
    -------
    configparser.RawConfigParser
        the parsed config
    """
    config = configparser.RawConfigParser()
    config.read(DEFAULT_AWS_CONFIG_PATH)

    return config

def get_script_arguments():
    parser = argparse.ArgumentParser(usage="usage: %(prog)s [options]",
                                     description="Wazuh wodle for monitoring AWS",
                                     formatter_class=argparse.RawTextHelpFormatter)
    # only one must be present (bucket or service)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-b', '--bucket', dest='logBucket', help='Specify the S3 bucket containing AWS logs',
                       action='store')
    group.add_argument('-sr', '--service', dest='service', help='Specify the name of the service',
                       action='store')
    parser.add_argument('-O', '--aws_organization_id', dest='aws_organization_id',
                        help='AWS organization ID for logs', required=False)
    parser.add_argument('-c', '--aws_account_id', dest='aws_account_id',
                        help='AWS Account ID for logs', required=False,
                        type=arg_valid_accountid)
    parser.add_argument('-d', '--debug', action='store', dest='debug', default=0, help='Enable debug')
    parser.add_argument('-a', '--access_key', dest='access_key', default=None,
                        help='S3 Access key credential. '
                             f'{DEPRECATED_MESSAGE.format(name="access_key", release="4.4", url=CREDENTIALS_URL)}')
    parser.add_argument('-k', '--secret_key', dest='secret_key', default=None,
                        help='S3 Access key credential. '
                             f'{DEPRECATED_MESSAGE.format(name="secret_key", release="4.4", url=CREDENTIALS_URL)}')
    # Beware, once you delete history it's gone.
    parser.add_argument('-R', '--remove', action='store_true', dest='deleteFile',
                        help='Remove processed files from the AWS S3 bucket', default=False)
    parser.add_argument('-p', '--aws_profile', dest='aws_profile', help='The name of credential profile to use',
                        default=None)
    parser.add_argument('-i', '--iam_role_arn', dest='iam_role_arn',
                        help='ARN of IAM role to assume for access to S3 bucket',
                        default=None)
    parser.add_argument('-n', '--aws_account_alias', dest='aws_account_alias',
                        help='AWS Account ID Alias', default='')
    parser.add_argument('-l', '--trail_prefix', dest='trail_prefix',
                        help='Log prefix for S3 key',
                        default='', type=arg_valid_prefix)
    parser.add_argument('-L', '--trail_suffix', dest='trail_suffix',
                        help='Log suffix for S3 key',
                        default='', type=arg_valid_prefix)
    parser.add_argument('-s', '--only_logs_after', dest='only_logs_after',
                        help='Only parse logs after this date - format YYYY-MMM-DD',
                        default=None, type=arg_valid_date)
    parser.add_argument('-r', '--regions', dest='regions', help='Comma delimited list of AWS regions to parse logs',
                        default='', type=arg_valid_regions)
    parser.add_argument('-e', '--skip_on_error', action='store_true', dest='skip_on_error',
                        help='If fail to parse a file, error out instead of skipping the file')
    parser.add_argument('-o', '--reparse', action='store_true', dest='reparse',
                        help='Parse the log file, even if its been parsed before', default=False)
    parser.add_argument('-t', '--type', dest='type', type=str, help='Bucket type.', default='cloudtrail')
    parser.add_argument('-g', '--aws_log_groups', dest='aws_log_groups', help='Name of the log group to be parsed',
                        default='')
    parser.add_argument('-P', '--remove-log-streams', action='store_true', dest='deleteLogStreams',
                        help='Remove processed log streams from the log group', default=False)
    parser.add_argument('-df', '--discard-field', type=str, dest='discard_field', default=None,
                        help='The name of the event field where the discard_regex should be applied to determine if '
                             'an event should be skipped.', )
    parser.add_argument('-dr', '--discard-regex', type=str, dest='discard_regex', default=None,
                        help='REGEX value to be applied to determine whether an event should be skipped.', )
    parser.add_argument('-st', '--sts_endpoint', type=str, dest='sts_endpoint', default=None,
                        help='URL for the VPC endpoint to use to obtain the STS token.')
    parser.add_argument('-se', '--service_endpoint', type=str, dest='service_endpoint', default=None,
                        help='URL for the endpoint to use to obtain the logs.')
    parser.add_argument('-rd', '--iam_role_duration', type=arg_valid_iam_role_duration, dest='iam_role_duration',
                        default=None,
                        help='The duration, in seconds, of the role session. Value can range from 900s to the max'
                             ' session duration set for the role.')
    parsed_args = parser.parse_args()

    if parsed_args.iam_role_duration is not None and parsed_args.iam_role_arn is None:
        raise argparse.ArgumentTypeError('Used --iam_role_duration argument but no --iam_role_arn provided.')

    return parsed_args

def main(argv):
    # Parse arguments
    options = get_script_arguments()

    if int(options.debug) > 0:
        global debug_level
        debug_level = int(options.debug)
        debug('+++ Debug mode on - Level: {debug}'.format(debug=options.debug), 1)

    try:
        if options.logBucket:
            if options.type.lower() == 'cloudtrail':
                bucket_type = buckets_s3.cloudtrail.AWSCloudTrailBucket
            elif options.type.lower() == 'vpcflow':
                bucket_type = buckets_s3.vpcflow.AWSVPCFlowBucket
            elif options.type.lower() == 'config':
                bucket_type = buckets_s3.config.AWSConfigBucket
            elif options.type.lower() == 'custom':
                bucket_type = buckets_s3.aws_bucket.AWSCustomBucket
            elif options.type.lower() == 'guardduty':
                bucket_type = buckets_s3.guardduty.AWSGuardDutyBucket
            elif options.type.lower() == 'cisco_umbrella':
                bucket_type = buckets_s3.umbrella.CiscoUmbrella
            elif options.type.lower() == 'waf':
                bucket_type = buckets_s3.waf.AWSWAFBucket
            elif options.type.lower() == 'alb':
                bucket_type = buckets_s3.load_balancers.AWSALBBucket
            elif options.type.lower() == 'clb':
                bucket_type = buckets_s3.load_balancers.AWSCLBBucket
            elif options.type.lower() == 'nlb':
                bucket_type = buckets_s3.load_balancers.AWSNLBBucket
            elif options.type.lower() == 'server_access':
                bucket_type = buckets_s3.server_access.AWSServerAccess
            else:
                raise Exception("Invalid type of bucket")
            bucket = bucket_type(reparse=options.reparse, access_key=options.access_key,
                                 secret_key=options.secret_key,
                                 profile=options.aws_profile,
                                 iam_role_arn=options.iam_role_arn,
                                 bucket=options.logBucket,
                                 only_logs_after=options.only_logs_after,
                                 skip_on_error=options.skip_on_error,
                                 account_alias=options.aws_account_alias,
                                 prefix=options.trail_prefix,
                                 suffix=options.trail_suffix,
                                 delete_file=options.deleteFile,
                                 aws_organization_id=options.aws_organization_id,
                                 region=options.regions[0] if options.regions else None,
                                 discard_field=options.discard_field,
                                 discard_regex=options.discard_regex,
                                 sts_endpoint=options.sts_endpoint,
                                 service_endpoint=options.service_endpoint,
                                 iam_role_duration=options.iam_role_duration
                                 )
            # check if bucket is empty or credentials are wrong
            bucket.check_bucket()
            bucket.iter_bucket(options.aws_account_id, options.regions)
        elif options.service:
            if options.service.lower() == 'inspector':
                service_type = services.inspector.AWSInspector
            elif options.service.lower() == 'cloudwatchlogs':
                service_type = services.cloudwatchlogs.AWSCloudWatchLogs
            else:
                raise Exception("Invalid type of service")

            if not options.regions:
                aws_config = get_aws_config_params()

                aws_profile = options.aws_profile or "default"

                if aws_config.has_option(aws_profile, "region"):
                    options.regions.append(aws_config.get(aws_profile, "region"))
                else:
                    debug("+++ Warning: No regions were specified, trying to get events from all regions", 1)
                    options.regions = ALL_REGIONS

            for region in options.regions:
                debug('+++ Getting alerts from "{}" region.'.format(region), 1)
                service = service_type(reparse=options.reparse,
                                       access_key=options.access_key,
                                       secret_key=options.secret_key,
                                       aws_profile=options.aws_profile,
                                       iam_role_arn=options.iam_role_arn,
                                       only_logs_after=options.only_logs_after,
                                       region=region,
                                       aws_log_groups=options.aws_log_groups,
                                       remove_log_streams=options.deleteLogStreams,
                                       discard_field=options.discard_field,
                                       discard_regex=options.discard_regex,
                                       sts_endpoint=options.sts_endpoint,
                                       service_endpoint=options.service_endpoint,
                                       iam_role_duration=options.iam_role_duration
                                       )
                service.get_alerts()

    except Exception as err:
        debug("+++ Error: {}".format(err), 2)
        if debug_level > 0:
            raise
        print("ERROR: {}".format(err))
        sys.exit(12)


if __name__ == '__main__':
    try:
        debug('Args: {args}'.format(args=str(sys.argv)), 2)
        signal.signal(signal.SIGINT, handler)
        main(sys.argv[1:])
        sys.exit(0)
    except Exception as e:
        print("Unknown error: {}".format(e))
        if debug_level > 0:
            raise
        sys.exit(1)