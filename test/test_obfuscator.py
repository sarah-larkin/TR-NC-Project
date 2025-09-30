from obfuscator.obfuscator import get_csv, obfuscate_csv, obfuscator
from moto import mock_aws  #TODO: only mock_s3 needed? 
from moto.core import patch_client
#import aws
import pytest
import pandas as pd
from botocore.exceptions import ClientError
from copy import deepcopy

#fixtures mocking the s3_client, mock_bucket and mock_file can be found in test/conftest.py file.

class TestGetCSV: 
    def test_returns_df(self, mock_bucket, mock_file, s3_client): 
        response = get_csv(mock_bucket, mock_file, s3_client) 
        assert isinstance(response, pd.DataFrame)
    
    def test_returns_content_from_the_named_csv_file(self, mock_bucket, mock_file, s3_client):
        df = get_csv(mock_bucket, mock_file, s3_client) 
        assert list(df.columns) == ['name', 'address']  #df.keys() also works 
        assert list(df.loc[0]) == ['PersonA', 'Earth']
        assert list(df.loc[1]) == ['PersonB', 'Mars']
    
    def test_get_csv_raises_exception_if_csv_is_empty(self, mock_bucket, s3_client): 
        empty_file = 'empty_file.csv'
        s3_client.put_object(Bucket=mock_bucket,  
                            Key=empty_file,
                            Body=b'')
        with pytest.raises(pd.errors.EmptyDataError) as exc: 
            get_csv(mock_bucket, empty_file, s3_client) 
        assert exc.value.args[0] == 'No columns to parse from file'  #TODO: check this out further, error message could change with new versions 

    def test_raises_clienterror_if_file_does_not_exist(self, mock_bucket, s3_client):
        """testing get_csv returns a client error for missing/incorrect file name"""
        non_file = 'nonexistent_file.csv'
        with pytest.raises(ClientError): 
            get_csv(mock_bucket, non_file, s3_client)
       
    def test_clienterror_error_code_when_file_does_not_exist(self, mock_bucket, s3_client):
        """testing specific exception code is NoSuchKey for missing/incorrect file name"""
        incorrect_key = "incorrect_filename.csv"
        with pytest.raises(ClientError) as exc: 
            get_csv(mock_bucket, incorrect_key, s3_client) 
        err = exc.value.response['Error']
        assert err["Code"] == 'NoSuchKey'

    # def test_file_type(self): #better name needed
    #     #not uploading JSON with .csv extension
    #     pass

    # def test_file_has_missing_data(self):
    #     #eg. ID = int, name = str
    #     #necessary here? 
    #     pass

    # def test_columns_contain_correct_data_type(self):
    #     #is this necessary? 
    #     pass 
            
    """check approriate error is raised/logged if error occurs
        #Exceptions:
        # S3.Client.exceptions.NoSuchKey
        # S3.Client.exceptions.InvalidObjectState"""

class TestObfuscateCSV: 
    def test_obfuscate_csv(self): 
        #test for purity 
        pass
    def test_new_object_returned(self):
        d = {'col1': [1, 2], 'col2': [3, 4]}
        data = pd.DataFrame(d)
        fields = ['col1', 'col2']
        
        result = obfuscate_csv(data, fields)

        assert isinstance(result, pd.DataFrame)
        assert result is not data

    def test_original_data_is_not_mutated(self):
        d = {'col1': [1, 2], 'col2': [3, 4]}
        data = pd.DataFrame(d)
        fields = ['col1', 'col2']

        copy_of_original = deepcopy(data)
        
        result = obfuscate_csv(data, fields)

        assert isinstance(result, pd.DataFrame)
        pd.testing.assert_frame_equal(data, copy_of_original)




class TestObfuscator: 
    #check bucket name is valid and exists
    #check file name is valid and exists 
    def test_obfuscator(self): 
        pass