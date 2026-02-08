import os
import time
import jwt as jwt_lib
import requests


class GitHubAppAuth:
    def __init__(self):
        self.app_id = os.getenv('GITHUB_APP_ID')
        self.private_key = os.getenv('GITHUB_PRIVATE_KEY', '').replace('\\n', '\n')
        self.installation_id = os.getenv('GITHUB_INSTALLATION_ID')
        
        # Validate required environment variables
        if not self.app_id:
            raise ValueError("GITHUB_APP_ID environment variable is required")
        if not self.private_key:
            raise ValueError("GITHUB_PRIVATE_KEY environment variable is required")
        if not self.installation_id:
            raise ValueError("GITHUB_INSTALLATION_ID environment variable is required")
            
        print(f"DEBUG: GitHubAppAuth initialized - App ID: {self.app_id}, Installation: {self.installation_id}")
        
    def get_app_token(self):
        """Generate JWT token for GitHub App"""
        try:
            import jwt as jwt_lib
            
            now = int(time.time())
            payload = {
                'iat': now,
                'exp': now + 600,  # 10 minutes
                'iss': self.app_id
            }
            
            print(f"DEBUG: JWT payload: {payload}")
            print(f"DEBUG: Private key first 100 chars: {self.private_key[:100]}")
            
            # Try to encode the JWT
            token = jwt_lib.encode(payload, self.private_key, algorithm='RS256')
            print(f"DEBUG: Generated JWT token: {token[:50]}...")
            
            return token
            
        except Exception as e:
            print(f"DEBUG: JWT encoding error: {str(e)}")
            print(f"DEBUG: Private key format check:")
            print(f"  - Starts with -----BEGIN: {self.private_key.startswith('-----BEGIN')}")
            print(f"  - Contains PRIVATE KEY: {'PRIVATE KEY' in self.private_key}")
            print(f"  - Ends with -----END: {'-----END' in self.private_key}")
            print(f"  - Length: {len(self.private_key)}")
            raise Exception(f"Failed to generate JWT token: {str(e)}")
    
    def get_installation_token(self):
        """Get installation access token"""
        try:
            app_token = self.get_app_token()
            
            headers = {
                'Authorization': f'Bearer {app_token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'Excel-Processor-App/1.0'
            }
            
            url = f'https://api.github.com/app/installations/{self.installation_id}/access_tokens'
            print(f"DEBUG: Requesting installation token from: {url}")
            print(f"DEBUG: Headers: {headers}")
            
            response = requests.post(url, headers=headers, timeout=10)
            
            print(f"DEBUG: Installation token response: {response.status_code}")
            print(f"DEBUG: Response headers: {dict(response.headers)}")
            print(f"DEBUG: Response body: {response.text}")
            
            if response.status_code == 201:
                token_data = response.json()
                return token_data['token']
            else:
                raise Exception(f"Failed to get installation token: {response.status_code} {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"DEBUG: Network error getting installation token: {str(e)}")
            raise Exception(f"Network error: {str(e)}")
        except Exception as e:
            print(f"DEBUG: Error getting installation token: {str(e)}")
            raise
    
    def delete_artifact_by_job_id(self, job_id):
        """Delete GitHub artifact by job_id (artifact name is processed-excel-{job_id})"""
        try:
            github_token = self.get_installation_token()
            github_repo = os.getenv('GITHUB_REPO', 'jewseppi/xlsvc')
            artifact_name = f"processed-excel-{job_id}"
            
            headers = {
                'Authorization': f'Bearer {github_token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'Excel-Processor-App/1.0'
            }
            
            # List artifacts to find the one we want to delete
            list_url = f'https://api.github.com/repos/{github_repo}/actions/artifacts'
            print(f"DEBUG: Listing artifacts to find: {artifact_name}")
            
            response = requests.get(list_url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                print(f"DEBUG: Failed to list artifacts: {response.status_code} {response.text}")
                return False
            
            artifacts = response.json().get('artifacts', [])
            artifact_id = None
            
            for artifact in artifacts:
                if artifact.get('name') == artifact_name:
                    artifact_id = artifact.get('id')
                    break
            
            if not artifact_id:
                print(f"DEBUG: Artifact {artifact_name} not found (may have already been deleted)")
                return False
            
            # Delete the artifact
            delete_url = f'https://api.github.com/repos/{github_repo}/actions/artifacts/{artifact_id}'
            print(f"DEBUG: Deleting artifact {artifact_name} (ID: {artifact_id})")
            
            delete_response = requests.delete(delete_url, headers=headers, timeout=10)
            
            if delete_response.status_code == 204:
                print(f"DEBUG: Successfully deleted artifact {artifact_name}")
                return True
            else:
                print(f"DEBUG: Failed to delete artifact: {delete_response.status_code} {delete_response.text}")
                return False
                
        except Exception as e:
            print(f"DEBUG: Error deleting artifact: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
