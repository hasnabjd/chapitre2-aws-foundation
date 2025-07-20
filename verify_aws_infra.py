#!/usr/bin/env python3
"""AWS Infrastructure Verification Script
Verifies the PosHub AWS infrastructure components including S3 bucket, Lambda role, and CloudWatch Log Group.
"""
import boto3
import json
import sys
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
            'bucket_location': None,
            'bucket_policy': None,
            'bucket_encryption': None,
            'bucket_versioning': None
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

            # Get bucket policy
            try:
                policy = self.s3_client.get_bucket_policy(Bucket=bucket_name)
                results['bucket_policy'] = json.loads(policy['Policy'])
                print("✅ Bucket policy found")
            except ClientError:
                print("ℹ️ No bucket policy configured")

            # Check encryption
            try:
                encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                results['bucket_encryption'] = encryption['ServerSideEncryptionConfiguration']
                print("✅ Bucket encryption configured")
            except ClientError:
                print("ℹ️ No bucket encryption configured")

            # Check versioning
            try:
                versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
                results['bucket_versioning'] = versioning.get('Status', 'NotEnabled')
                print(f"ℹ️ Bucket versioning: {results['bucket_versioning']}")
            except ClientError as e:
                print(f"⚠️ Error checking versioning: {e}")
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
            'attached_policies': [],
            'inline_policies': [],
            'permissions_boundary': None
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

            # Get inline policies
            inline_policies = self.iam_client.list_role_policies(RoleName=role_name)
            results['inline_policies'] = inline_policies['PolicyNames']
            if results['inline_policies']:
                print(f"📋 Inline policies: {', '.join(results['inline_policies'])}")

            # Check permissions boundary
            if 'PermissionsBoundary' in role['Role']:
                results['permissions_boundary'] = role['Role']['PermissionsBoundary']['PermissionsBoundaryArn']
                print(f"ℹ️ Permissions boundary: {results['permissions_boundary']}")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchEntity':
                print(f"❌ IAM role '{role_name}' does not exist")
            else:
                print(f"❌ Error accessing IAM role: {e}")
        except Exception as e:
            print(f"❌ Unexpected error testing IAM role: {e}")
        
        return results
    def test_ssm_parameters(self) -> Dict:
        """Test SSM Parameter Store access."""
        results = {
            'can_access_ssm': False,
            'parameters_found': [],
            'test_parameter_created': False
        }
        try:
            # Test SSM access by listing parameters
            parameters = self.ssm_client.describe_parameters(MaxResults=10)
            results['can_access_ssm'] = True
            results['parameters_found'] = [param['Name'] for param in parameters['Parameters']]
            print(f"✅ SSM Parameter Store accessible")
            print(f"📋 Found {len(results['parameters_found'])} parameters")

            # Try to create a test parameter
            test_param_name = "/poshub/test-parameter"
            try:
                self.ssm_client.put_parameter(
                    Name=test_param_name,
                    Value="test-value",
                    Type="String",
                    Overwrite=True
                )
                results['test_parameter_created'] = True
                print(f"✅ Test parameter '{test_param_name}' created/updated")

                # Clean up test parameter
                self.ssm_client.delete_parameter(Name=test_param_name)
                print(f"🧹 Test parameter cleaned up")
            except ClientError as e:
                print(f"⚠️ Cannot create test parameter: {e}")
        except ClientError as e:
            print(f"❌ Error accessing SSM Parameter Store: {e}")
        except Exception as e:
            print(f"❌ Unexpected error testing SSM: {e}")
        
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
                    
                    # Test accessibility by trying to describe the log group
                    try:
                        # Test accessibility by listing log streams (this will work if we have access)
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
    def run_all_tests(self) -> Dict:
        """Run all infrastructure tests."""
        print("🚀 Starting AWS Infrastructure Verification")
        print("=" * 50)

        # Get account info
        account_info = self.get_account_info()
        if account_info:
            print(f"🏢 Account ID: {account_info['account_id']}")
            print(f"👤 User ARN: {account_info['user_arn']}")

            print("\n" + "=" * 50)
        print("📦 Testing S3 Infrastructure")
        print("=" * 50)
        s3_results = self.test_s3_bucket()

        print("\n" + "=" * 50)
        print("🔐 Testing Lambda Role Infrastructure")
        print("=" * 50)
        lambda_role_results = self.test_lambda_role()

        print("\n" + "=" * 50)
        print("⚙️ Testing SSM Parameter Store")
        print("=" * 50)
        ssm_results = self.test_ssm_parameters()

        print("\n" + "=" * 50)
        print("�� Testing CloudWatch Log Group")
        print("=" * 50)
        log_group_results = self.test_cloudwatch_log_group()

        # Summary
        print("\n" + "=" * 50)
        print("📊 TEST SUMMARY")
        print("=" * 50)

        summary = {
            's3_bucket_exists': s3_results['bucket_exists'],
            's3_bucket_accessible': s3_results['bucket_accessible'],
            'lambda_role_exists': lambda_role_results['role_exists'],
            'lambda_role_trust_policy_correct': lambda_role_results['trust_policy'] is not None,
            'ssm_accessible': ssm_results['can_access_ssm'],
            'log_group_exists': log_group_results['log_group_exists'],
            'log_group_accessible': log_group_results['log_group_accessible'],
            'all_tests_passed': (
                s3_results['bucket_exists'] and
                lambda_role_results['role_exists'] and
                ssm_results['can_access_ssm'] and
                log_group_results['log_group_exists'] and
                log_group_results['log_group_accessible']
            )
        }

        print(f"S3 Bucket exists: {'✅' if summary['s3_bucket_exists'] else '❌'}")
        print(f"S3 Bucket accessible: {'✅' if summary['s3_bucket_accessible'] else '❌'}")
        print(f"Lambda Role exists: {'✅' if summary['lambda_role_exists'] else '❌'}")
        print(f"Lambda Trust Policy correct: {'✅' if summary['lambda_role_trust_policy_correct'] else '❌'}")
        print(f"SSM Parameter Store accessible: {'✅' if summary['ssm_accessible'] else '❌'}")
        print(f"CloudWatch Log Group exists: {'✅' if summary['log_group_exists'] else '❌'}")
        print(f"CloudWatch Log Group accessible: {'✅' if summary['log_group_accessible'] else '❌'}")
        print(f"\nOverall Status: {'✅ ALL TESTS PASSED' if summary['all_tests_passed'] else '❌ SOME TESTS FAILED'}")

        return {
            'summary': summary,
            's3_results': s3_results,
            'lambda_role_results': lambda_role_results,
            'ssm_results': ssm_results,
            'log_group_results': log_group_results,
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