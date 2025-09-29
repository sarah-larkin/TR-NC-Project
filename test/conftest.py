from moto import mock_aws #TODO: only mock_s3 needed? (mock_aws)
import os
import pytest
import boto3


@pytest.fixture(scope='module', autouse=True)
def aws_credentials():
    """mocked aws credentials for moto"""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"]='eu-west-2'

@pytest.fixture(scope='module')  #TODO: update to yield_fixture??
def s3_client(aws_credentials):
    """mocked s3 client"""
    with mock_aws():      #could also be mock_aws
        yield boto3.client('s3', region_name='eu-west-2') #TODO:checkout session instead of hard coding region

@pytest.fixture(scope='module')
def mock_bucket(s3_client):
    """mocked s3 bucket"""
    name = 'test_bucket_TR_NC'
    s3_client.create_bucket(
        Bucket=name,
        CreateBucketConfiguration={'LocationConstraint': 'eu-west-2'}
    )
    return name

@pytest.fixture(scope='module')
def mock_file(s3_client, mock_bucket): 
    file_name = 'test_file.csv'
    s3_client.put_object(Bucket=mock_bucket,  #consider upload_fileobj for replicating larger file size
                      Key=file_name,
                      Body=b'name, address,\nJohn, Earth,\n') #byte string (docs state: Body=b'bytes'|file,)
    return file_name
#consider returning a dict with {"bucket": mock_bucket, "key": file_name} if likely to need more than just the key in future tests. 
