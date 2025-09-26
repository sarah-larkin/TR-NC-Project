from obfuscator.obfuscator import get_csv, obfuscate_csv, obfuscator
import boto3
from moto import mock_aws
from moto.core import patch_client
import os
#import aws
import pytest
import pandas as pd


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
        yield boto3.client('s3', region_name='eu-west-2')

@pytest.fixture
def bucket(s3):
    name = 'test_bucket_TR_NC'
    s3.create_bucket(
        Bucket=name,
        CreateBucketConfiguration={'LocationConstraint': 'eu-west-2'}
    )
    return name
    # with open('test.txt', 'rb') as f:
    #     s3.put_object(
    #                     Body=f, 
    #                     Bucket='test_bucket_TR_NC',
    #                     Key='data/test.txt'
    #                 )
        

class TestGetCSV: 
    def test_get_csv_function_returns_df(self, s3, bucket): 
        #create/use mock bucket --> fixture passed in          
        #put text csv in test bucket:
        s3.put_object(Bucket=bucket, 
                      Key='test.csv',
                      Body="name, address,\nJohn, Earth,\n".encode('utf-8'))
        #run get_csv()
        response = get_csv(bucket,'test.csv')
        #assert output type == pd.df 
        assert isinstance(response, pd.DataFrame)
        
        

#check bucket name is valid and exists
#check file name is valid and exists 
#check approriate error is raised/logged if error occurs
#check function returns a df 

class TestObfuscateCSV: 
    def test_obfuscate_csv(self): 
        #test for purity 
        pass

class TestObfuscator: 
    def test_obfuscator(self): 
        pass