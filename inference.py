import boto3
from sagemaker import get_execution_role
sm_client = boto3.client(service_name='sagemaker')
runtime_sm_client = boto3.client(service_name='sagemaker-runtime')
account_id = boto3.client('sts').get_caller_identity()['Account']
region = boto3.Session().region_name
endpoint_name = 'seshat-technique-endpoint'
import json
content_type = "application/json"
request_body = {"input": "rundll32.exe adds the blbdigital Registry Run key using RegSetValueExA()"}
data = json.loads(json.dumps(request_body))
payload = json.dumps(data)
response = runtime_sm_client.invoke_endpoint(
    EndpointName=endpoint_name,
    ContentType=content_type,
    Body=payload)
result = json.loads(response['Body'].read().decode())
print(result)
