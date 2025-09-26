import json
import logging

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__) #TODO: add logging to code 



#Helper functions 
def get_csv(bucket, file_name): 
    """
    function summary: 
    accesses the specified S3 bucket and retrieve the csv file. 

    args: 
    bucket - retrieved from json passed to obfuscator()
    file_name - retrieved from json passed to obfuscator()

    returns: 
    csv/bytes object to be used in the obfuscator function. 

    """
    #use boto3 here 
    s3 = boto3.client('s3')

    s3.get_object(Bucket=bucket, Key=file_name)
#TODO: check AWS secrets manager to connect to account? 
#dict reader? 

    pass

def obfuscate_csv(data:bytes, fields:list) -> bytes:   #TODO: use this style for all? 
    """
    function summary: 
    Pure function taking the data from the csv, and obfuscating the columns with the 
    specified headings (fields). 

    args: 
    data - bytes (returned from get_csv())
    fields - list (from JSON passed to obfuscator())    

    returns:
    new csv bytes, exact copy of original but with relevant columns obfuscated.  
    """
    
    pass


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

    exceptions: #TODO
    """

    #validate JSON string 
        #file location valid
        #file type = csv
        #fields valid
        #fields type = list of strings 
        #both elements present 
    #define bucket 
    #define file_name 
    #define fields 

    csv_data = get_csv(bucket, file_name)

    obfuscated_bytes = obfuscate_csv(data, fields)

    #return obfuscated_bytes

    pass





if (__name__ == "__main__"):
    pass
#to run script as is and for testing. 






#TODO: confirm security, PEP8 compliance
