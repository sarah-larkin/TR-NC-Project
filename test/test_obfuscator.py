from obfuscator.obfuscator import get_csv, obfuscate_csv, obfuscator
import boto3
from moto import mock_aws
from moto.core import patch_client
import os
import aws
import pytest


@pytest.fixture(scope='module', autouse=True)
def aws_credentials():
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"]='eu-west-2'

@pytest.fixture(scope='module')
def s3(aws_credentials):
    with mock_aws():
        yield boto3.client('s3', region_name='eu-west-1')

@pytest.fixture
def bucket(s3):
    s3.create_bucket(
        Bucket='test_bucket_TR_NC',
        CreateBucketConfiguration={'LocationConstraint': 'eu-west-2'}
    )
    with open('test.txt', 'rb') as f:
        s3.put_object(
                        Body=f, 
                        Bucket='test_bucket_TR_NC',
                        Key='data/test.txt'
                    )
        
@mock_aws
class TestGetCSV: 
    def test_csv(self): 
        #mocking required (moto)
        pass 

class TestObfuscateCSV: 
    def test_obfuscate_csv(self): 
        #test for purity 
        pass

class TestObfuscator: 
    def test_obfuscator(self): 
        pass