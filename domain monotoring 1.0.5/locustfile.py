import uuid
import random
from locust import HttpUser, task, between
import io

class UserBehavior(HttpUser):
    wait_time = between(1, 3)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.username = None
        self.password = None
        self.user_id = None
        self.registered_users = []  # Store registered users for login
        self.sample_domains = [
            "www.google.com",
            "test.com",
            "demo.org",
            "sample.net",
            "testsite.io"
        ]
    
    def on_start(self):
        """Initialize user-specific data when the test starts."""
        self.password = f"TestPass_{uuid.uuid4().hex[:8]}"

    @task(1)
    def register_user(self):
        """Register a new user and store credentials for login."""
        self.username = f"user_{uuid.uuid4().hex[:8]}"
        payload = {"username": self.username, "password": self.password}
        
        with self.client.post("/register", 
                            json=payload, 
                            catch_response=True) as response:
            
            if response.status_code == 200:
                response.success()
                print(f"Successfully registered user: {self.username}")
                # Store credentials for future login attempts
                self.registered_users.append({
                    "username": self.username,
                    "password": self.password,
                    "user_id": response.json().get("user_id", str(uuid.uuid4()))  # Assuming user_id is returned in response
                })
            else:
                response.failure(f"Failed to register user. Status code: {response.status_code}. Response: {response.text}")
    
    @task(2)
    def login_user(self):
        """Login with either a newly registered user or a random existing user."""
        if not self.registered_users:
            print("No registered users available for login")
            return
        
        user = random.choice(self.registered_users)
        payload = {
            "username": user["username"],
            "password": user["password"]
        }
        
        with self.client.post("/", 
                            json=payload, 
                            catch_response=True) as response:
            
            if response.status_code == 200:
                response.success()
                self.user_id = user["user_id"]
                print(f"Successfully logged in user: {user['username']}")
            else:
                response.failure(f"Login failed. Status code: {response.status_code}. Response: {response.text}")

    @task(1)
    def add_domain(self):
        """Add a single domain for a logged-in user."""
        if not self.user_id:
            return
        
        domain = random.choice(self.sample_domains)
        payload = {
            "user_id": self.user_id,
            "domain": domain
        }
        
        with self.client.post("/add_domain_page", 
                            json=payload, 
                            catch_response=True) as response:
            
            if response.status_code in [200, 208]:  # Accept both OK and ALREADY_REPORTED
                response.success()
                print(f"Successfully added domain {domain} for user {self.user_id}")
            else:
                response.failure(f"Failed to add domain. Status: {response.status_code}. Response: {response.text}")

    @task(1)
    def delete_domain(self):
        """Delete a domain for a logged-in user."""
        if not self.user_id:
            return
        
        domain = random.choice(self.sample_domains)
        payload = {
            "user_id": self.user_id,
            "domain": domain
        }
        
        with self.client.post("/domains/delete", 
                            json=payload, 
                            catch_response=True) as response:
            
            if response.status_code in [200, 208]:
                response.success()
                print(f"Successfully deleted domain {domain} for user {self.user_id}")
            else:
                response.failure(f"Failed to delete domain. Status: {response.status_code}. Response: {response.text}")

    # @task(1)
    # def get_user_domains(self):
    #     """Get all domains for a logged-in user."""
    #     if not self.user_id:
    #         return
        
    #     with self.client.get(f"/domains/user/{self.user_id}", 
    #                        catch_response=True) as response:
            
    #         if response.status_code == 200:
    #             response.success()
    #             print(f"Successfully retrieved domains for user {self.user_id}")
    #         else:
    #             response.failure(f"Failed to get domains. Status: {response.status_code}. Response: {response.text}")

    @task(1)
    def bulk_upload_invalid_file(self):
        """Test bulk upload with invalid file extension."""
        if not self.user_id:
            return
        
        domains_content = "\n".join(self.sample_domains)
        
        # Using invalid file extension to test backend validation
        files = {
            'file': ('domains.csv', io.StringIO(domains_content), 'text/plain')
        }
        
        form_data = {'user_id': self.user_id}
        
        with self.client.post("/domain_files",
                            data=form_data,
                            files=files,
                            catch_response=True) as response:
            
            if response.status_code == 401 and "invalid file format" in response.json().get('message', ''):
                response.success()  # This is expected behavior for invalid file
                print(f"Successfully tested invalid file format rejection")
            else:
                response.failure(f"Unexpected response for invalid file. Status: {response.status_code}")

class QuickStartUser(UserBehavior):
    """
    Wrapper class that inherits from UserBehavior.
    This is the class that Locust will use to run the tests.
    """
    min_wait = 1000
    max_wait = 3000