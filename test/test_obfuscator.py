from obfuscator.obfuscator import get_csv, obfuscate_csv, obfuscator
import boto3
from moto import mock_aws  #TODO: only mock_s3 needed? 
from moto.core import patch_client
import os
#import aws
import pytest
import pandas as pd


class TestGetCSV: 
    def test_get_csv_function_returns_df(self, s3_client, mock_bucket): 
        #create/use mock bucket --> fixture passed in          
        #put text csv in test bucket:
        s3_client.put_object(Bucket=mock_bucket, 
                      Key='test.csv',
                      Body="name, address,\nJohn, Earth,\n".encode('utf-8')) #TODO: string accepted (docs state: Body=b'bytes'|file,)
        #run get_csv()
        response = get_csv(mock_bucket,'test.csv')
        #assert output type == pd.df 
        assert isinstance(response, pd.DataFrame)
        #TODO: other assertions required?? 
    def test_get_csv_function_raises_client_error(self, s3_client):
        pass

        
    #check approriate error is raised/logged if error occurs


class TestObfuscateCSV: 
    def test_obfuscate_csv(self): 
        #test for purity 
        pass

class TestObfuscator: 
    #check bucket name is valid and exists
    #check file name is valid and exists 
    def test_obfuscator(self): 
        pass