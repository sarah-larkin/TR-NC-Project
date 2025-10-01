import json
import csv
import logging
import pandas as pd

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG) #alter level if needed [debug, info, warning, error, critical]

s3 = boto3.client('s3')

#Helper functions 
def get_csv(bucket:str, file_name:str, s3:object) -> pd.DataFrame: 
    """access the specified S3 bucket and retrieve the csv file. 

    args: 
    bucket - retrieved from json passed to obfuscator()
    file_name - retrieved from json passed to obfuscator()

    returns: 
    Pandas DataFrame 

    Exceptions: 
    Raises ClientError NoSuchKey if file name is not present. 
    Raises ClientError InvalidObjectState if file is archived and needs to be retored prior to accessing. 
    Raises Pandas EmptyDataError if the file being retrieved is empty. 
    """
    try:
        csv_file_object = s3.get_object(Bucket=bucket, Key=file_name)   #dict 
        logging.info('csv file successfully retrieved')
        
        df = pd.read_csv(csv_file_object['Body'])
        return df

    except pd.errors.EmptyDataError as error: 
        logging.error('the file you are trying to retrieve does not contain any data')
        raise error
    except ClientError as error:
        logging.error('the file does not exist, check filename')
        #TODO: what if it is an InvalidObjectState exception?
        raise error
    # S3.Client.exceptions.NoSuchKey
    # S3.Client.exceptions.InvalidObjectState

    
def obfuscate_data(data:pd.DataFrame, fields:list) -> bytes:  #TODO: confirm if returning bytes or df #TODO: use this style for all? 
    """obfuscating the values under the headings defined in fields list.  

    args: 
    data - pd.DataFrame (returned from get_csv()) 
    fields - list (from JSON passed to obfuscator())    

    returns:
    new csv bytes, exact copy of original but with relevant columns obfuscated.  
    """
    df = data.copy()

    for heading in fields:
        valid_columns = list(df.columns) 
        if heading not in valid_columns: 
            logger.warning(f"{heading} is an invalid header name")
            return "invalid heading"
        #if datatype is not str log a warning 
        #TODO: check how to specify specific fields within the pd and put in the warning
        else: 
            df[heading] = "xxx"

    return df


#Primary function 
def obfuscator(input_json): 
    """ 
    function summary:
    produce a copy of the csv file specified in the input_json (location of file/pii fields 
    to obfuscate) with the specified columns obsuscated so sensitive information remains
    anonymous. 

    args: 
    JSON string containing: 
    - file to obfuscate - S3 location of the required CSV file for obfuscation 
    - pii fields - names of the fields that are required to be obfuscated

    returns: 
    new byte string object containing an exact copy of the input file but with
    the specified sensitive data replaced with obfuscated string (boto3 put_object compatible).
    (The calling procedure will handle saving returned bytes from this function)

    exceptions: #TODO: list exceptions 
    """

    #validate JSON string 
        #file location valid
        #file type = csv  - if extended one of the valid file types handled
        #fields valid (headings)
        #fields type = list of strings 
        #both elements present 

    bucket = input_json["file_to_obfuscate"] #update
    file_name = input_json["file_to_obfuscate"]#update
    fields = input_json["pii_fields"]

    """setup with extension in mind"""
    #if file_name[-4:] == ".csv": 
        #data = get_csv(bucket, file_name)
        #obfuscated_df = obfuscate_data(data, fields)
        #csv_output = obfuscated_df.to_csv()
        #return csv_output 


    #return bytestream
    pass





if (__name__ == "__main__"):
    pass
#to run script as is and for testing. 


if (__name__ == "__main__"):
    get_csv(bucket='tr-nc-test-source-files', file_name='Titanic-Dataset.csv', s3=s3)




#TODO: confirm security, PEP8 compliance
