from obfuscator.obfuscator import get_csv, obfuscate_csv, obfuscator
from moto import mock_aws  #TODO: only mock_s3 needed? 
from moto.core import patch_client
#import aws
import pytest
import pandas as pd
from botocore.exceptions import ClientError

#fixtures mocking the s3_client, mock_bucket and mock_file can be found in test/conftest.py file.

class TestGetCSV: 
    def test_get_csv_function_returns_df(self, mock_bucket, mock_file, s3_client): 
        response = get_csv(mock_bucket, mock_file, s3_client) 
        assert isinstance(response, pd.DataFrame)
    
    def test_get_csv_returns_content_from_the_named_csv_file(self, mock_bucket, mock_file, s3_client):
        df = get_csv(mock_bucket, mock_file, s3_client) 
        assert list(df.columns) == ['name', 'address']  #df.keys() also works 
        assert list(df.loc[0]) == ['PersonA', 'Earth']
        assert list(df.loc[1]) == ['PersonB', 'Mars']

    def test_get_csv_returns_error_if_csv_is_empty(self, mock_bucket, s3_client): #error/excpetion?
        empty_file = 'empty_file.csv'
        s3_client.put_object(Bucket=mock_bucket,  
                            Key=empty_file,
                            Body=b'')
        with pytest.raises(pd.errors.EmptyDataError) as exc: 
            get_csv(mock_bucket, empty_file, s3_client) 
        assert exc.value.args[0] == 'No columns to parse from file'  

    def test_returns_error_if_file_does_not_exist(self):
        pass

    def test_get_csv_function_raises_client_error_for_incorrect_file_name(self, mock_bucket, s3_client):
        incorrect_key = "incorrect_filename.csv"
        with pytest.raises(ClientError) as exc: 
            get_csv(mock_bucket, incorrect_key, s3_client) 
        err = exc.value.response['Error']
        assert err["Code"] == 'NoSuchKey'


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