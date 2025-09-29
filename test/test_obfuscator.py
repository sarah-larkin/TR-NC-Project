from obfuscator.obfuscator import get_csv, obfuscate_csv, obfuscator
import boto3
from moto import mock_aws  #TODO: only mock_s3 needed? 
from moto.core import patch_client
import os
#import aws
import pytest
import pandas as pd
from botocore.exceptions import ClientError

#fixtures mocking the s3_client, mock_bucket and mock_file can be found in test/conftest.py file.

class TestGetCSV: 
    def test_get_csv_function_returns_df(self, mock_bucket, mock_file): 
        response = get_csv(mock_bucket, mock_file) 
        assert isinstance(response, pd.DataFrame)
        #TODO: other assertions required??
    
    def test_get_csv_returns_content_from_the_named_csv_file(self):
        pass

    def test_get_csv_returns_error_if_csv_is_empty(self): #error/excpetion?
        pass

    def test_returns_error_if_file_does_not_exist(self):
        pass

    def test_get_csv_function_raises_client_error_for_incorrect_file_name(self, s3_client, mock_bucket):
        incorrect_key = "incorrect_filename.csv"
        with pytest.raises(ClientError): 
            get_csv(mock_bucket, incorrect_key) 

    def test_file_type(self): #better name needed
        #not uploading JSON with .csv extension
        pass
            
    """check approriate error is raised/logged if error occurs
        #Exceptions:
        # S3.Client.exceptions.NoSuchKey
        # S3.Client.exceptions.InvalidObjectState"""

class TestObfuscateCSV: 
    def test_obfuscate_csv(self): 
        #test for purity 
        pass

class TestObfuscator: 
    #check bucket name is valid and exists
    #check file name is valid and exists 
    def test_obfuscator(self): 
        pass