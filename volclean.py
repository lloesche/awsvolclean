#!/usr/bin/env python3
import boto3
import boto3.session
from datetime import datetime, timedelta
import sys
import argparse
import logging
from multiprocessing.pool import ThreadPool
from pprint import pprint

logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(logging.DEBUG)
logging.getLogger('VolumeCleaner').setLevel(logging.DEBUG)
log = logging.getLogger(__name__)


def main(argv):
    p = argparse.ArgumentParser(description='Generate AWS IAM User Report')
    p.add_argument('--access-key-id', '-k', help='AWS Access Key ID', dest='access_key_id')
    p.add_argument('--secret-access-key', '-s', help='AWS Secret Access Key', dest='secret_access_key')
    p.add_argument('--region', '-r', help='AWS Region', dest='region', required=True)
    p.add_argument('--run-dont-ask', help='Assume YES to all questions', action='store_true', default=False,
                   dest='all_yes')
    p.add_argument('--pool-size', '-p', help='Thread Pool Size - how many AWS API requests we do in parallel',
                   dest='pool_size', default=10, type=int)
    args = p.parse_args(argv)

    vol_clean = VolumeCleaner(args)
    vol_clean.run()


class VolumeCleaner:
    def __init__(self, args):
        self.args = args
        self.log = logging.getLogger(__name__)

    def run(self):
        p = ThreadPool(self.args.pool_size)
        candidates = list(filter(None, p.map(self.candidate, self.available_volumes())))
        if len(candidates) > 0 \
                and (self.args.all_yes or query_yes_no('Do you want to remove {} Volumes?'.format(len(candidates)))):
            self.log.info('Removing {} Volumes in Region {}'.format(len(candidates), self.args.region))
            p.map(self.remove_volume, candidates)
            self.log.info('Done')
        else:
            self.log.info('Not doing anything')

    def available_volumes(self):
        self.log.debug('Finding unused Volumes in Region {}'.format(self.args.region))
        session = boto3.session.Session(aws_access_key_id=self.args.access_key_id,
                                        aws_secret_access_key=self.args.secret_access_key,
                                        region_name=self.args.region)
        ec2 = session.resource('ec2')
        volumes = ec2.volumes.filter(Filters=[{'Name': 'status', 'Values': ['available']}])
        self.log.info('Found {} unused Volumes'.format(len(list(volumes))))
        return volumes

    # based on http://blog.ranman.org/cleaning-up-aws-with-boto3/
    def get_metrics(self, volume, days=14):
        self.log.debug('Retrieving Metrics for Volume {}'.format(volume.volume_id))
        session = boto3.session.Session(aws_access_key_id=self.args.access_key_id,
                                        aws_secret_access_key=self.args.secret_access_key,
                                        region_name=self.args.region)
        cw = session.client('cloudwatch')

        end_time = datetime.now() + timedelta(days=1)
        start_time = end_time - timedelta(days=days)

        return cw.get_metric_statistics(
            Namespace='AWS/EBS',
            MetricName='VolumeIdleTime',
            Dimensions=[{'Name': 'VolumeId', 'Value': volume.volume_id}],
            Period=3600,
            StartTime=start_time,
            EndTime=end_time,
            Statistics=['Minimum'],
            Unit='Seconds'
        )

    def candidate(self, volume):
        metrics = self.get_metrics(volume)
        for metric in metrics['Datapoints']:
            if metric['Minimum'] < 299:
                self.log.debug('Volume {} is no candidate for deletion'.format(volume.volume_id))
                return None

        self.log.debug('Volume {} is a candidate for deletion'.format(volume.volume_id))
        return volume

    def remove_volume(self, volume, thread_safe=True):
        self.log.debug('Removing Volume {}'.format(volume.volume_id))
        if thread_safe:
            session = boto3.session.Session(aws_access_key_id=self.args.access_key_id,
                                            aws_secret_access_key=self.args.secret_access_key,
                                            region_name=self.args.region)
            ec2 = session.resource('ec2')
            volume = ec2.Volume(volume.volume_id)

        volume.delete()


# From http://stackoverflow.com/questions/3041986/apt-command-line-interface-like-yes-no-input
def query_yes_no(question, default='no'):
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


if __name__ == "__main__":
    main(sys.argv[1:])