# awsvolclean
AWS Volume Cleaner
```
usage: volclean.py [-h] [--access-key-id ACCESS_KEY_ID]
                   [--secret-access-key SECRET_ACCESS_KEY]
                   [--region REGION [REGION ...]] [--run-dont-ask]
                   [--pool-size POOL_SIZE] [--age AGE]
                   [--tags TAGS [TAGS ...]] [--ignore-metrics] [--verbose]

Remove unused EBS volumes

optional arguments:
  -h, --help            show this help message and exit
  --access-key-id ACCESS_KEY_ID, -k ACCESS_KEY_ID
                        AWS Access Key ID
  --secret-access-key SECRET_ACCESS_KEY, -s SECRET_ACCESS_KEY
                        AWS Secret Access Key
  --region REGION [REGION ...], -r REGION [REGION ...]
                        AWS Region (default: all)
  --run-dont-ask, -y    Assume YES to all questions
  --pool-size POOL_SIZE, -p POOL_SIZE
                        Thread Pool Size - how many AWS API requests we do in parallel (default: 10)
  --age AGE, -a AGE     Days after which a Volume is considered orphaned (default: 14)
  --tags TAGS [TAGS ...], -t TAGS [TAGS ...]
                        Tag filter in format "key:regex" (E.g. Name:^integration-test)
  --ignore-metrics, -i  Ignore Volume Metrics - remove all detached Volumes
  --verbose, -v         Verbose logging
```
