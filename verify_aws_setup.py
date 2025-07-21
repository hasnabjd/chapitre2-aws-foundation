#!/usr/bin/env python3
"""
AWS Infrastructure Verification Script
Vérifie l'infrastructure complète et effectue les tests demandés :
- Lit /pos/api-key depuis SSM
- Écrit "hello CW" dans le log group
- Test round-trip S3 (upload/download)
"""

import boto3
import json
import sys
import uuid
from botocore.exceptions import ClientError, NoCredentialsError
from typing import Dict, List, Tuple

class AWSInfraVerifier:
    def __init__(self):
        """Initialize AWS clients for different services."""
        try:
            self.s3_client = boto3.client('s3')
            self.iam_client = boto3.client('iam')
            self.sts_client = boto3.client('sts')
            self.ssm_client = boto3.client('ssm')
            self.logs_client = boto3.client('logs')
            print("✅ AWS clients initialized successfully")
        except NoCredentialsError:
            print("❌ AWS credentials not found. Please configure your AWS credentials.")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error initializing AWS clients: {e}")
            sys.exit(1)

    def get_account_info(self) -> Dict:
        """Get AWS account information."""
        try:
            identity = self.sts_client.get_caller_identity()
            return {
                'account_id': identity['Account'],
                'user_arn': identity['Arn'],
                'user_id': identity['UserId']
            }
        except Exception as e:
            print(f"❌ Error getting account info: {e}")
            return {}

    def test_s3_bucket(self, bucket_name: str = "poshub-dev-bucket") -> Dict:
        """Test S3 bucket existence and permissions."""
        results = {
            'bucket_exists': False,
            'bucket_accessible': False,
            'bucket_location': None
        }
        
        try:
            # Check if bucket exists
            self.s3_client.head_bucket(Bucket=bucket_name)
            results['bucket_exists'] = True
            print(f"✅ S3 bucket '{bucket_name}' exists")

            # Get bucket location
            location = self.s3_client.get_bucket_location(Bucket=bucket_name)
            results['bucket_location'] = location.get('LocationConstraint') or 'us-east-1'
            print(f"📍 Bucket location: {results['bucket_location']}")

            # Check bucket accessibility
            try:
                self.s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
                results['bucket_accessible'] = True
                print("✅ Bucket is accessible")
            except ClientError as e:
                print(f"⚠️ Bucket accessibility issue: {e}")
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchBucket':
                print(f"❌ S3 bucket '{bucket_name}' does not exist")
            else:
                print(f"❌ Error accessing S3 bucket: {e}")
        except Exception as e:
            print(f"❌ Unexpected error testing S3 bucket: {e}")
        
        return results

    def test_lambda_role(self, role_name: str = "poshub-lambda-role-h") -> Dict:
        """Test Lambda role existence and attached policies."""
        results = {
            'role_exists': False,
            'role_arn': None,
            'trust_policy': None,
            'attached_policies': []
        }
        
        try:
            # Get role details
            role = self.iam_client.get_role(RoleName=role_name)
            results['role_exists'] = True
            results['role_arn'] = role['Role']['Arn']
            results['trust_policy'] = role['Role']['AssumeRolePolicyDocument']
            print(f"✅ IAM role '{role_name}' exists")
            print(f"📍 Role ARN: {results['role_arn']}")

            # Check trust policy
            trust_principal = results['trust_policy']['Statement'][0]['Principal']
            if 'Service' in trust_principal and 'lambda.amazonaws.com' in trust_principal['Service']:
                print("✅ Trust policy correctly configured for Lambda")
            else:
                print("❌ Trust policy not configured for Lambda")

            # Get attached policies
            attached_policies = self.iam_client.list_attached_role_policies(RoleName=role_name)
            results['attached_policies'] = [policy['PolicyName'] for policy in attached_policies['AttachedPolicies']]
            print(f"📋 Attached policies: {', '.join(results['attached_policies'])}")

            # Check for required policies
            required_policies = ['S3PosDevRW-h', 'CloudWatchLogsWrite-h', 'SSMParameterPolicy-h']
            missing_policies = [policy for policy in required_policies if policy not in results['attached_policies']]
            if missing_policies:
                print(f"⚠️ Missing policies: {', '.join(missing_policies)}")
            else:
                print("✅ All required policies are attached")
                
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchEntity':
                print(f"❌ IAM role '{role_name}' does not exist")
            else:
                print(f"❌ Error accessing IAM role: {e}")
        except Exception as e:
            print(f"❌ Unexpected error testing IAM role: {e}")
        
        return results

    def test_cloudwatch_log_group(self, log_group_name: str = "/aws/lambda/poshub-dev-h") -> Dict:
        """Test CloudWatch Log Group existence and configuration."""
        results = {
            'log_group_exists': False,
            'log_group_accessible': False,
            'retention_days': None,
            'log_group_arn': None
        }
        
        try:
            # Check if log group exists
            log_groups = self.logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
            
            # Check if our specific log group exists
            for log_group in log_groups['logGroups']:
                if log_group['logGroupName'] == log_group_name:
                    results['log_group_exists'] = True
                    results['log_group_arn'] = log_group['arn']
                    results['retention_days'] = log_group.get('retentionInDays')
                    print(f"✅ CloudWatch Log Group '{log_group_name}' exists")
                    print(f"📍 Log Group ARN: {results['log_group_arn']}")
                    
                    if results['retention_days']:
                        print(f"⏰ Retention period: {results['retention_days']} days")
                    else:
                        print("ℹ️ No retention policy set (logs kept indefinitely)")
                    
                    # Test accessibility by trying to list log streams
                    try:
                        self.logs_client.describe_log_streams(logGroupName=log_group_name, limit=1)
                        results['log_group_accessible'] = True
                        print("✅ Log group is accessible")
                    except ClientError as e:
                        print(f"⚠️ Log group accessibility issue: {e}")
                    break
            else:
                print(f"❌ CloudWatch Log Group '{log_group_name}' does not exist")
                
        except ClientError as e:
            print(f"❌ Error accessing CloudWatch Logs: {e}")
        except Exception as e:
            print(f"❌ Unexpected error testing CloudWatch Log Group: {e}")
        
        return results

    def test_ssm_parameter(self, param_name: str = "/pos-h/api-key") -> Dict:
        """Test SSM parameter existence and read access."""
        results = {
            'parameter_exists': False,
            'parameter_accessible': False,
            'parameter_value': None,
            'parameter_type': None
        }
        
        try:
            # Try to get the parameter
            response = self.ssm_client.get_parameter(
                Name=param_name,
                WithDecryption=True
            )
            
            results['parameter_exists'] = True
            results['parameter_accessible'] = True
            results['parameter_value'] = response['Parameter']['Value']
            results['parameter_type'] = response['Parameter']['Type']
            
            print(f"✅ SSM parameter '{param_name}' exists")
            print(f"📋 Parameter type: {results['parameter_type']}")
            print(f"🔐 Parameter value: {results['parameter_value'][:10]}..." if len(results['parameter_value']) > 10 else f"🔐 Parameter value: {results['parameter_value']}")
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ParameterNotFound':
                print(f"❌ SSM parameter '{param_name}' does not exist")
                print(f"💡 You can create it with: aws ssm put-parameter --name '{param_name}' --value 'your-api-key' --type 'SecureString'")
            else:
                print(f"❌ Error accessing SSM parameter: {e}")
        except Exception as e:
            print(f"❌ Unexpected error testing SSM parameter: {e}")
        
        return results

    def test_ssm_parameter_reading(self, param_name: str = "/pos-h/api-key") -> Dict:
        """Test reading SSM parameter like in the user's script."""
        results = {
            'parameter_read_success': False,
            'parameter_value': None
        }
        
        try:
            # Read parameter like in the user's script
            response = self.ssm_client.get_parameter(
                Name=param_name,
                WithDecryption=False  # Like in the user's script
            )
            
            results['parameter_read_success'] = True
            results['parameter_value'] = response['Parameter']['Value']
            
            print(f"✅ /pos-h/api-key param value: {results['parameter_value']}")
            
        except ClientError as e:
            print(f"❌ Error getting /pos-h/api-key param: {e}")
        except Exception as e:
            print(f"❌ Unexpected error reading SSM parameter: {e}")
        
        return results

    def test_s3_round_trip(self, bucket_name: str = "poshub-dev-bucket") -> Dict:
        """Test S3 round-trip: upload a file and download it back."""
        results = {
            'upload_success': False,
            'download_success': False,
            'round_trip_success': False,
            'test_file_name': None
        }
        
        try:
            # Generate test file content and name
            test_content = f"Test file created at {boto3.Session().region_name}\nTimestamp: {boto3.client('sts').get_caller_identity()['Account']}"
            test_file_name = f"test-{uuid.uuid4()}.txt"
            results['test_file_name'] = test_file_name
            
            print(f"📤 Uploading test file '{test_file_name}' to S3...")
            
            # Upload file to S3
            self.s3_client.put_object(
                Bucket=bucket_name,
                Key=test_file_name,
                Body=test_content.encode('utf-8')
            )
            results['upload_success'] = True
            print(f"✅ File uploaded successfully to s3://{bucket_name}/{test_file_name}")
            
            # Download file from S3
            print(f"📥 Downloading file '{test_file_name}' from S3...")
            response = self.s3_client.get_object(
                Bucket=bucket_name,
                Key=test_file_name
            )
            downloaded_content = response['Body'].read().decode('utf-8')
            
            if downloaded_content == test_content:
                results['download_success'] = True
                results['round_trip_success'] = True
                print(f"✅ File downloaded successfully and content matches")
            else:
                print(f"❌ Downloaded content doesn't match original")
            
            # Clean up test file
            print(f"🧹 Cleaning up test file '{test_file_name}'...")
            self.s3_client.delete_object(
                Bucket=bucket_name,
                Key=test_file_name
            )
            print(f"✅ Test file cleaned up")
            
        except ClientError as e:
            print(f"❌ Error during S3 round-trip test: {e}")
        except Exception as e:
            print(f"❌ Unexpected error during S3 round-trip test: {e}")
        
        return results

    def test_cloudwatch_logging(self, log_group_name: str = "/aws/lambda/poshub-dev-h") -> Dict:
        """Test writing to CloudWatch Log Group."""
        results = {
            'log_writing_success': False,
            'log_stream_name': None
        }
        
        try:
            # Create a log stream name
            log_stream_name = f"test-stream-{uuid.uuid4()}"
            results['log_stream_name'] = log_stream_name
            
            print(f"📝 Writing 'hello CW' to CloudWatch Log Group...")
            
            # Create log stream
            self.logs_client.create_log_stream(
                logGroupName=log_group_name,
                logStreamName=log_stream_name
            )
            
            # Write log event with proper timestamp (like in the user's script)
            import time
            self.logs_client.put_log_events(
                logGroupName=log_group_name,
                logStreamName=log_stream_name,
                logEvents=[
                    {
                        'timestamp': int(time.time() * 1000),  # Use current timestamp in milliseconds
                        'message': 'hello CW'
                    }
                ]
            )
            
            results['log_writing_success'] = True
            print(f"✅ Successfully wrote 'hello CW' to CloudWatch Log Group")
            print(f"📍 Log Stream: {log_stream_name}")
            
        except ClientError as e:
            print(f"❌ Error writing to CloudWatch Log Group: {e}")
        except Exception as e:
            print(f"❌ Unexpected error writing to CloudWatch Log Group: {e}")
        
        return results

    def run_all_tests(self) -> Dict:
        """Run all infrastructure tests."""
        print("🚀 Starting AWS Infrastructure Verification")
        print("=" * 60)

        # Get account info
        account_info = self.get_account_info()
        if account_info:
            print(f"🏢 Account ID: {account_info['account_id']}")
            print(f"👤 User ARN: {account_info['user_arn']}")

        print("\n" + "=" * 60)
        print("📦 Testing S3 Infrastructure")
        print("=" * 60)
        s3_results = self.test_s3_bucket()

        print("\n" + "=" * 60)
        print("🔐 Testing Lambda Role Infrastructure")
        print("=" * 60)
        lambda_role_results = self.test_lambda_role()

        print("\n" + "=" * 60)
        print("📊 Testing CloudWatch Log Group")
        print("=" * 60)
        log_group_results = self.test_cloudwatch_log_group()

        print("\n" + "=" * 60)
        print("⚙️ Testing SSM Parameter Store")
        print("=" * 60)
        ssm_results = self.test_ssm_parameter()

        print("\n" + "=" * 60)
        print("🔄 Testing S3 Round-Trip")
        print("=" * 60)
        s3_round_trip_results = self.test_s3_round_trip()

        print("\n" + "=" * 60)
        print("📝 Testing CloudWatch Logging")
        print("=" * 60)
        cw_logging_results = self.test_cloudwatch_logging()

        print("\n" + "=" * 60)
        print("🔐 Testing SSM Parameter Reading (like user script)")
        print("=" * 60)
        ssm_reading_results = self.test_ssm_parameter_reading()

        # Summary
        print("\n" + "=" * 60)
        print("📊 TEST SUMMARY")
        print("=" * 60)

        summary = {
            's3_bucket_exists': s3_results['bucket_exists'],
            's3_bucket_accessible': s3_results['bucket_accessible'],
            'lambda_role_exists': lambda_role_results['role_exists'],
            'lambda_role_trust_policy_correct': lambda_role_results['trust_policy'] is not None,
            'log_group_exists': log_group_results['log_group_exists'],
            'log_group_accessible': log_group_results['log_group_accessible'],
            'ssm_parameter_exists': ssm_results['parameter_exists'],
            'ssm_parameter_accessible': ssm_results['parameter_accessible'],
            's3_round_trip_success': s3_round_trip_results['round_trip_success'],
            'cloudwatch_logging_success': cw_logging_results['log_writing_success'],
            'ssm_parameter_reading_success': ssm_reading_results['parameter_read_success'],
            'all_tests_passed': (
                s3_results['bucket_exists'] and
                s3_results['bucket_accessible'] and
                lambda_role_results['role_exists'] and
                log_group_results['log_group_exists'] and
                log_group_results['log_group_accessible'] and
                ssm_results['parameter_exists'] and
                ssm_results['parameter_accessible'] and
                s3_round_trip_results['round_trip_success'] and
                cw_logging_results['log_writing_success'] and
                ssm_reading_results['parameter_read_success']
            )
        }

        print(f"S3 Bucket exists: {'✅' if summary['s3_bucket_exists'] else '❌'}")
        print(f"S3 Bucket accessible: {'✅' if summary['s3_bucket_accessible'] else '❌'}")
        print(f"Lambda Role exists: {'✅' if summary['lambda_role_exists'] else '❌'}")
        print(f"Lambda Trust Policy correct: {'✅' if summary['lambda_role_trust_policy_correct'] else '❌'}")
        print(f"CloudWatch Log Group exists: {'✅' if summary['log_group_exists'] else '❌'}")
        print(f"CloudWatch Log Group accessible: {'✅' if summary['log_group_accessible'] else '❌'}")
        print(f"SSM Parameter exists: {'✅' if summary['ssm_parameter_exists'] else '❌'}")
        print(f"SSM Parameter accessible: {'✅' if summary['ssm_parameter_accessible'] else '❌'}")
        print(f"S3 Round-trip successful: {'✅' if summary['s3_round_trip_success'] else '❌'}")
        print(f"CloudWatch Logging successful: {'✅' if summary['cloudwatch_logging_success'] else '❌'}")
        print(f"SSM Parameter Reading successful: {'✅' if summary['ssm_parameter_reading_success'] else '❌'}")
        print(f"\nOverall Status: {'✅ ALL TESTS PASSED' if summary['all_tests_passed'] else '❌ SOME TESTS FAILED'}")

        return {
            'summary': summary,
            's3_results': s3_results,
            'lambda_role_results': lambda_role_results,
            'log_group_results': log_group_results,
            'ssm_results': ssm_results,
            's3_round_trip_results': s3_round_trip_results,
            'cw_logging_results': cw_logging_results,
            'account_info': account_info
        }

def main():
    """Main function to run the verification."""
    verifier = AWSInfraVerifier()
    results = verifier.run_all_tests()

    # Exit with appropriate code
    if results['summary']['all_tests_passed']:
        print("\n🎉 Infrastructure verification completed successfully!")
        sys.exit(0)
    else:
        print("\n⚠️ Some infrastructure components need attention.")
        sys.exit(1)

if __name__ == "__main__":
    main() 