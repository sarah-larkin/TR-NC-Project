# GDPR Obfuscator

This is a general purpose tool that accesses data files (csv or json) in an
AWS S3 bucket and obfuscates personally identifiable information (PII). 
- It accepts a JSON string detailing the bucket/file details and PII fields. 
- It returns a bytestream object to be used as the 'Body' argument to boto3's 'put_object()'.

## Contents
- Tech stack
- Requirements
- Installation
- Usage
- Testing
- Author


## Tech Stack
- Python 
- boto3
- pandas
- pip-audit

for testing (optional)
- pytest
- pytest-testdox
- moto

## Requirements 

It is expected that the user has: 
- AWS account
- S3 bucket(s) with csv/json files that require obfuscation
- IAM permissions to access the named S3 bucket
- Locally configured AWS credentials 

#### AWS credentials options:
No credentials should be stored in this repo instead use: 
- 'aws configure' 
- IAM role 
- environment variables: 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'


## Installation (if modifying)
- clone repo
```bash
git clone https://github.com/sarah-larkin/TR-NC-Project.git
```
- create venv 
```
python -m venv venv
```
- activate venv 
```
source venv/bin/activate 
```
- install dependencies
```python
pip install -r requirements.txt
pip install -r requirements_dev.txt
```


## Usage 
- import module 
```
from obfuscator.obfuscator import obfuscator 
```
- example function call:  
```
obfuscator(
    '{"file_to_obfuscate": "s3://tr-nc-test-source-files/customer_data.csv",'
     '"pii_fields": ["gender", "age"]}'
)
```
- example using the boto3 put_object: 
```
body = obfuscator('{"file_to_obfuscate": "s3://tr-nc-test-source-files/customer_data.csv","pii_fields": ["gender", "age"]}')

s3.put_object(
    Body=body,
    Bucket='tr-nc-test-obfs-files',
    Key= 'obfs_cust_data.csv')
```

## Testing 

If required, to run the tests, run the following command in the terminal: 
```python
pytest --testdox -vvrp test/test_obfuscator.py
```
## Authors
- [@sarah-larkin](https://github.com/sarah-larkin)