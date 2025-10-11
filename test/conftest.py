from moto import mock_aws 
import os
import pytest
import boto3
import pandas as pd
import numpy as np


@pytest.fixture(scope='function', autouse=True)
def aws_credentials():
    """mocked aws credentials for moto"""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"]='eu-west-2'

@pytest.fixture(scope='function')  
def mock_s3_client(aws_credentials):
    """mocked s3 client"""
    with mock_aws():     
        yield boto3.client('s3', region_name='eu-west-2') #TODO:checkout session instead of hard coding region

@pytest.fixture(scope='function')
def mock_bucket(mock_s3_client):
    """mocked s3 bucket"""
    name = 'test_bucket_TR_NC'
    mock_s3_client.create_bucket(
        Bucket=name,
        CreateBucketConfiguration={'LocationConstraint': 'eu-west-2'}
    )
    return name


@pytest.fixture(scope='function')
def mock_csv_file_details(mock_s3_client, mock_bucket): # TODO: could add mock bucket? 
    """mocked csv file in s3 bucket, returns dict 
    (additional edge cases added to mock_df below)"""
    #file_name =    #'test_file.csv'
    mock_s3_client.put_object(
        Bucket=mock_bucket,  #consider upload_fileobj for replicating larger file size
        Key="test_file.csv",
        Body= b'Name,Email,Phone,DOB,Notes\nAlice,alice@example.com,+1-555-111-2222,1990-01-01,ok\nBob,bob_at_example.com,5551113333,1985-02-03\nCharlie,charlie@ex.co.uk,0,01/05/1975,no action'
        ) #byte string
    mock_details = {"Scheme" : "s3",
                "Bucket" : "test_bucket_TR_NC",
                "Key": "test_file.csv",  #could include 'folder' path eg. outer_folder/inner_folder/
                "File_Name": "test_file.csv",
                "File_Type": "csv"}
    return mock_details
 
#TODO: mock_csv_file_detaile(): check if need to include more edge cases here in the body added to the csv (like in mock_df)

@pytest.fixture(scope='function')
def mock_df(): 
    """mocked DataFrame"""
    d = {
    "Name": [                        
        "Alice",          # normal
        "Bob",            # normal
        "",               # empty string
        None,             # missing
        "Charlie",        # normal
        "Δelta",          # unicode
        123,              # non-string numeric
        "Eve",            # normal
    ],

    "Email": [
        "alice@example.com",
        "bob_at_example.com",  # malformed
        "",                    # empty
        None,                  # missing
        "charlie@ex.co.uk",
        42,                    # non-string numeric
        np.nan,                # NaN
        "eve+test@example.com",
    ],

    "Phone": [
        "+1-555-111-2222",
        "5551113333",
        "",                 # empty
        None,
        0,                  # numeric zero
        False,              # boolean
        np.nan,
        "(555) 999-0000",
    ],

    "DOB": [
        "1990-01-01",
        "1985-02-03",
        None,
        pd.NaT,             # pandas missing datetime
        "01/05/1975",
        "1970-12-31",
        "2000-07-07",
        "1999-09-09",
    ],
    "Notes": [
        "ok",
        "",
        "legacy",
        None,
        "no action",
        "special chars: ♥",
        "large text " * 2,
        "final row",
    ],
}
    return pd.DataFrame(d)
 
@pytest.fixture(scope='function') 
def mock_json_for_csv_file(): 
    """mocked input json string for a csv file"""
    mock_csv_json = '{"file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv", "pii_fields": ["Name", "Email", "Phone", "DOB"]}'
    return mock_csv_json

@pytest.fixture(scope='function') 
def mock_dict_for_csv_file():  # TODO: update name and tests
    """mocked python dict for a csv file"""
    mock_dict_for_csv = {"file_to_obfuscate": "s3://test_bucket_TR_NC/test_file.csv", "pii_fields": ["Name", "Email", "Phone", "DOB"]}
    return mock_dict_for_csv



