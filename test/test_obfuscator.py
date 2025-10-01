from obfuscator.obfuscator import get_csv, obfuscate_data, obfuscator
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
    """ fields: ["Name", "Email", "Phone", "DOB", "Notes"]""" #TODO: delete when done 
    def test_new_object_returned(self, mock_df):
        """ testing purity - checking new obejct is return"""
        result = obfuscate_data(mock_df, ["Email", "Phone", "DOB"] )
        assert isinstance(result, pd.DataFrame)
        assert result is not mock_df

    def test_original_data_is_not_mutated(self, mock_df):
        """ testing puring - checking original data has not been mutated"""
        copy_of_original = deepcopy(mock_df)
        result = obfuscate_data(mock_df, ["Email", "Phone", "DOB"])
        assert isinstance(result, pd.DataFrame)
        pd.testing.assert_frame_equal(mock_df, copy_of_original)

    def test_sensitive_data_is_replaced_by_xxx_in_one_column(self, mock_df): 
        result = obfuscate_data(mock_df, ["Email"])
        assert isinstance(result, pd.DataFrame)
        assert list(result.loc[0]) == ["Alice", 'xxx', "+1-555-111-2222", "1990-01-01", "ok"]
        assert list(result.loc[1]) == ["Bob", 'xxx', "5551113333", "1985-02-03",""]
        assert list(result.loc[7]) == ["Eve", 'xxx', "(555) 999-0000", "1999-09-09", "final row"]
    
    def test_sensitive_data_is_replaced_by_xxx_in_multiple_columns(self, mock_df): 
        result = obfuscate_data(mock_df, ["Email", "Phone", "DOB"])
        assert isinstance(result, pd.DataFrame)
        assert list(result.loc[0]) == ["Alice", 'xxx', 'xxx', 'xxx', "ok"]
        assert list(result.loc[1]) == ["Bob", 'xxx', 'xxx', 'xxx',""]
        assert list(result.loc[7]) == ["Eve", 'xxx', 'xxx', 'xxx', "final row"]
    
    def test_returns_error_msg_if_column_does_not_exist(self, mock_df): 
        result = obfuscate_data(mock_df, ["Address"])
        assert result == "invalid heading"

    def test_will_still_obfuscate_data_when_datatype_is_not_str(self, mock_df):
        result = obfuscate_data(mock_df, ["Name", "Email", "Phone", "DOB"])
        assert list(result.loc[2]) == ["xxx", "xxx", "xxx", "xxx", "legacy"]
        assert list(result.loc[3]) == ["xxx", "xxx", "xxx", "xxx", None]
        assert list(result.loc[4]) == ["xxx", "xxx", "xxx", "xxx", "no action"]
        assert list(result.loc[5]) == ["xxx", "xxx", "xxx", "xxx", "special chars: ♥"]
        assert list(result.loc[6]) == ["xxx", "xxx", "xxx", "xxx", "large text " * 2]





        # assert list(result.loc[2]) == ["", "", "", None, "legacy"]
        # assert list(result.loc[3]) == [None, None, None, pd.NaT, None]
        # assert list(result.loc[4]) == ["Charlie", "charlie@ex.co.uk", 0, "01/05/1975", "no action"]
        # assert list(result.loc[5]) == ["Δelta", 42, False, "1970-12-31", "special chars: ♥"]
        # assert list(result.loc[6]) == [123, np.nan, np.nan, "2000-07-07", "large text " * 2]

class TestObfuscator: 
    #check bucket name is valid and exists
    #check file name is valid and exists 
    def test_obfuscator(self): 
        pass