from obfuscator.obfuscator import get_csv, obfuscate_csv, obfuscator
import boto3
from moto import mock_aws
import os



@pytest.fixture(autouse=True)
def aws_credentials():
    """Mocked AWS Credentials for moto."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"]='eu-west-2'


@mock_aws
class TestGetCSV: 
    def test_csv(self): 
        #mocking required (moto)
        pass 

class TestObfuscateCSV: 
    def test_obfuscate_csv(self): 
        #test for purity 
        pass

class TestObfuscator: 
    def test_obfuscator(self): 
        pass